//! B-06 S18: sleep, wake and physical path changes of a running epoch.
//!
//! S17 pins the relay egress interface for the provider epoch, because a
//! route lookup after the full-wide settings names the tunnel. A Mac that
//! moves between wired and Wi-Fi loses that interface, so the provider
//! watches the physical path with a Network.framework path monitor that
//! prohibits the tunnel (`other`) and loopback interface types. A change of
//! the pinned interface's own relay-family addresses rebuilds the relay
//! session on it under `reasserting`; the loss of the pinned interface (or
//! of its last relay-family address) re-pins the epoch to the preferred
//! physical interface that holds such an address (its name and index,
//! checked against the kernel) and rebuilds. v33: a pin taken while it was
//! the path's primary follows the primary: another usable interface
//! becoming primary re-pins to it and rebuilds, because macOS then holds the
//! old interface's relay sockets (window-v32-ifswitch-r3). Other changes of
//! other interfaces never move a working pin. A tunnel, IPsec, loopback or
//! Apple peer-to-peer link is never picked. Path updates are coalesced:
//! one is acted on only after `QUIET` without another, or after `HOLD` of a
//! continuous burst, and the S17 backoff bounds the rebuilds.
//!
//! On wake the provider forces one immediate re-ACK while the lease is live,
//! and enters the S17 rebuild when the lease already lapsed during sleep (the
//! bridge clock keeps counting while the Mac sleeps). Sleep itself is only
//! recorded and completes at once.
use crate::{
    policy::Phase,
    provider_session_body::EpochPins,
    relay_socket::{self, InterfaceAddress, RelayInterface},
};
use std::{
    net::IpAddr,
    sync::{Arc, Mutex, PoisonError},
    time::{Duration, Instant},
};

/// Updates closer together than this are one change.
pub(crate) const QUIET: Duration = Duration::from_millis(500);
/// A burst that never goes quiet is still acted on after this.
pub(crate) const HOLD: Duration = Duration::from_secs(2);

/// Network.framework's `nw_interface_type_t`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InterfaceKind {
    Other,
    Wifi,
    Cellular,
    Wired,
    Loopback,
}

impl InterfaceKind {
    pub(crate) fn from_raw(raw: i32) -> Self {
        match raw {
            1 => Self::Wifi,
            2 => Self::Cellular,
            3 => Self::Wired,
            4 => Self::Loopback,
            _ => Self::Other,
        }
    }

    /// Only these may carry the relay; utun and ipsec report `Other`.
    fn physical(self) -> bool {
        matches!(self, Self::Wifi | Self::Cellular | Self::Wired)
    }
}

/// One interface of a reported path, in the path's preference order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PathInterface {
    pub(crate) name: String,
    pub(crate) index: u32,
    pub(crate) kind: InterfaceKind,
}

/// Whether `interface` may carry the relay: a physical type, a nonzero
/// index and a name that is never a tunnel, IPsec, loopback or peer-to-peer
/// link, whatever type it reports.
pub(crate) fn eligible(interface: &PathInterface) -> bool {
    interface.kind.physical()
        && interface.index != 0
        && !relay_socket::refused_name(&interface.name)
}

/// One physical egress a path offers: an eligible interface with its usable
/// addresses of the relay's family, sorted. Never empty in an observation:
/// an interface without such an address cannot carry the relay.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Egress {
    pub(crate) name: String,
    pub(crate) index: u32,
    pub(crate) addresses: Vec<IpAddr>,
}

/// One coalesced path report: every eligible interface that holds a usable
/// relay-family address, in the path's preference order. Empty: no
/// satisfied physical path the relay could use.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct PathObservation {
    pub(crate) usable: Vec<Egress>,
}

impl PathObservation {
    /// The preferred usable egress: the first one holding an address.
    pub(crate) fn primary(&self) -> Option<&Egress> {
        self.usable
            .iter()
            .find(|egress| !egress.addresses.is_empty())
    }

    /// The usable egress of `pinned` (same name and index), if it holds an
    /// address of the relay's family.
    fn egress_of(&self, pinned: &RelayInterface) -> Option<&Egress> {
        self.usable.iter().find(|egress| {
            egress.name == pinned.name()
                && egress.index == pinned.index()
                && !egress.addresses.is_empty()
        })
    }

    /// v33: whether `egress` (by name and index) is this path's primary.
    fn is_primary(&self, egress: &Egress) -> bool {
        self.primary()
            .is_some_and(|primary| primary.name == egress.name && primary.index == egress.index)
    }
}

fn link_local(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Observe one path: `interfaces` as the monitor reported them and the
/// kernel's `addresses` (getifaddrs), for a relay of family `v6`. Only an
/// eligible interface holding an up, non-link-local address of the relay's
/// family is usable.
pub(crate) fn observe(
    satisfied: bool,
    interfaces: &[PathInterface],
    v6: bool,
    addresses: &[InterfaceAddress],
) -> PathObservation {
    if !satisfied {
        return PathObservation::default();
    }
    let usable = interfaces
        .iter()
        .filter(|interface| eligible(interface))
        .filter_map(|chosen| {
            let mut held: Vec<IpAddr> = addresses
                .iter()
                .filter(|entry| {
                    entry.name == chosen.name
                        && entry.up
                        && !entry.loopback
                        && !entry.point_to_point
                        && entry.address.is_ipv6() == v6
                        && !link_local(entry.address)
                })
                .map(|entry| entry.address)
                .collect();
            held.sort();
            held.dedup();
            (!held.is_empty()).then(|| Egress {
                name: chosen.name.clone(),
                index: chosen.index,
                addresses: held,
            })
        })
        .collect();
    PathObservation { usable }
}

/// Coalesces path updates: the latest is due once `quiet` passed without
/// another, or once `hold` passed since the first of a burst.
#[derive(Debug)]
pub(crate) struct Debounce {
    quiet: Duration,
    hold: Duration,
    pending: Option<(PathObservation, Instant, Instant)>,
}

impl Default for Debounce {
    fn default() -> Self {
        Self::new(QUIET, HOLD)
    }
}

impl Debounce {
    pub(crate) fn new(quiet: Duration, hold: Duration) -> Self {
        Self {
            quiet,
            hold,
            pending: None,
        }
    }

    pub(crate) fn observe(&mut self, observed: PathObservation, now: Instant) {
        let first = self.pending.as_ref().map_or(now, |(_, first, _)| *first);
        self.pending = Some((observed, first, now));
    }

    /// The latest observation, once due; it is then taken.
    pub(crate) fn take_due(&mut self, now: Instant) -> Option<PathObservation> {
        let (_, first, last) = self.pending.as_ref()?;
        let quiet = now.saturating_duration_since(*last) >= self.quiet;
        let held = now.saturating_duration_since(*first) >= self.hold;
        if !(quiet || held) {
            return None;
        }
        self.pending.take().map(|(observed, _, _)| observed)
    }
}

/// What one coalesced observation does to the epoch's pin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum PathAction {
    /// No change of the pinned egress, no usable physical path, or nothing
    /// pinned yet.
    Ignore,
    /// The first observation, with the pinned interface usable: remember
    /// its egress as the baseline; nothing is rebuilt.
    Baseline(Egress),
    /// Re-pin to this egress and rebuild.
    Repin(Egress),
}

/// Judge one observation against the pin, the baseline (always the pinned
/// interface's own egress) and `follows`: whether the pin was the path's
/// primary egress when it was taken (the baseline or the last re-pin).
///
/// While the pinned interface stays usable (on the path, same index, holding
/// a relay-family address):
/// - v33: a pin that follows the primary moves with it: another usable
///   interface becoming the path's primary re-pins to that interface and
///   rebuilds. Installed v32 showed why (window-v32-ifswitch-r3): once a
///   plugged-in cable made en7 primary, macOS held every packet of the
///   provider's en0 relay sockets and sent new ones out en7 although they
///   were bound to en0, so the session was lost anyway when its lease ran
///   out (`capture_lease_expired`, 1.5 s later) and was rebuilt on the stale
///   en0 pin.
/// - Otherwise only a change of its own addresses rebuilds, on that same
///   interface. A pin that did not follow the primary (a multi-homed Mac
///   whose first route lookup named an interface behind the path's primary)
///   never moves while it works: another interface appearing, leaving,
///   becoming primary or changing leaves it alone.
///
/// Once the pinned interface is no longer usable the epoch re-pins to the
/// preferred usable egress. A path with no usable egress never re-pins: the
/// session keeps its pin (and fails closed) until one returns.
pub(crate) fn path_action(
    pinned: Option<&RelayInterface>,
    baseline: Option<&Egress>,
    follows: bool,
    observed: &PathObservation,
) -> PathAction {
    let Some(pinned) = pinned else {
        return PathAction::Ignore;
    };
    if let Some(current) = observed.egress_of(pinned) {
        let Some(last) = baseline else {
            return PathAction::Baseline(current.clone());
        };
        if follows && !observed.is_primary(current) {
            if let Some(primary) = observed.primary() {
                return PathAction::Repin(primary.clone());
            }
        }
        return if last == current {
            PathAction::Ignore
        } else {
            PathAction::Repin(current.clone())
        };
    }
    match observed.primary() {
        Some(primary) => PathAction::Repin(primary.clone()),
        None => PathAction::Ignore,
    }
}

/// What a re-pin does to the epoch in `phase`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RepinEffect {
    /// Running: seal the session with the recoverable `relay_path_changed`
    /// and rebuild under reasserting.
    Rebuild,
    /// Reasserting: the rebuild's next attempt binds to the new pin.
    NextAttempt,
    /// Not live: nothing to rebuild.
    Ignore,
}

pub(crate) fn repin_effect(phase: Phase) -> RepinEffect {
    match phase {
        Phase::Running => RepinEffect::Rebuild,
        Phase::Reasserting => RepinEffect::NextAttempt,
        _ => RepinEffect::Ignore,
    }
}

/// One epoch's path watch on the main runloop: the coalescer the monitor
/// queue feeds, the baseline egress, whether the pin follows the path's
/// primary (v33: it was the primary when taken) and the last observation
/// logged.
pub(crate) struct Watch {
    debounce: Arc<Mutex<Debounce>>,
    baseline: Option<Egress>,
    follows_primary: bool,
    logged: Option<Option<String>>,
}

impl Default for Watch {
    fn default() -> Self {
        Self::with(Debounce::default())
    }
}

impl Watch {
    pub(crate) fn with(debounce: Debounce) -> Self {
        Self {
            debounce: Arc::new(Mutex::new(debounce)),
            baseline: None,
            follows_primary: false,
            logged: None,
        }
    }

    /// The coalescer that path updates are fed into, from any queue.
    pub(crate) fn sink(&self) -> Arc<Mutex<Debounce>> {
        self.debounce.clone()
    }

    /// Feed one observation (the monitor queue does this).
    pub(crate) fn feed(sink: &Mutex<Debounce>, observed: PathObservation, now: Instant) {
        sink.lock()
            .unwrap_or_else(PoisonError::into_inner)
            .observe(observed, now);
    }

    /// Act on a due observation at `now`: true once the epoch's interface
    /// was re-pinned (to the interface `admit` checked), which the caller
    /// follows with exactly one rebuild.
    pub(crate) fn poll(
        &mut self,
        now: Instant,
        pins: &EpochPins,
        admit: impl FnOnce(&str, u32) -> Result<RelayInterface, &'static str>,
    ) -> bool {
        let due = self
            .debounce
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_due(now);
        let Some(observed) = due else {
            return false;
        };
        let name = observed.primary().map(|egress| egress.name.clone());
        if self.logged.as_ref() != Some(&name) {
            match &name {
                Some(name) => crate::apple::log_code("path_change", &format!("name:{name}")),
                None => crate::apple::log_code("path_change", "unsatisfied"),
            }
            self.logged = Some(name);
        }
        match path_action(
            pins.get().as_ref(),
            self.baseline.as_ref(),
            self.follows_primary,
            &observed,
        ) {
            PathAction::Ignore => false,
            PathAction::Baseline(current) => {
                self.follows_primary = observed.is_primary(&current);
                self.baseline = Some(current);
                false
            }
            PathAction::Repin(target) => match admit(&target.name, target.index) {
                Ok(interface) => {
                    pins.repin(&interface);
                    // v27: the drop counters' `primary` class follows the pin.
                    crate::leak_guard::LEAK_GUARD.set_primary(Some(interface.name().as_bytes()));
                    crate::apple::log_code(
                        "relay_interface_repinned",
                        &format!("name:{}", interface.name()),
                    );
                    self.follows_primary = observed.is_primary(&target);
                    self.baseline = Some(target);
                    true
                }
                Err(code) => {
                    crate::apple::log_code("relay_interface_repin_refused", code);
                    false
                }
            },
        }
    }
}

/// What a wake does to the epoch in `phase`, whose session lease is `live`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WakeAction {
    /// The lease survived sleep: one immediate re-ACK.
    Reack,
    /// The lease lapsed while asleep: the S17 rebuild under reasserting.
    Rebuild,
    /// Already rebuilding under reasserting (typically because the drain
    /// timer saw the lapsed lease before NE delivered the wake).
    Reasserting,
    /// No running epoch.
    Ignore,
}

impl WakeAction {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Reack => "reack",
            Self::Rebuild => "rebuild",
            Self::Reasserting => "reasserting",
            Self::Ignore => "idle",
        }
    }
}

pub(crate) fn wake_action(phase: Phase, live: bool) -> WakeAction {
    match phase {
        Phase::Running if live => WakeAction::Reack,
        Phase::Running => WakeAction::Rebuild,
        Phase::Reasserting => WakeAction::Reasserting,
        _ => WakeAction::Ignore,
    }
}

/// The Network.framework path monitor of one epoch, restricted to physical
/// interface types. Its updates run on its own serial queue and only feed
/// the coalescer; the main runloop polls it.
pub(crate) struct PathMonitor {
    raw: std::ptr::NonNull<std::ffi::c_void>,
    _queue: dispatch2::DispatchRetained<dispatch2::DispatchQueue>,
}

mod nw {
    use block2::DynBlock;
    use std::ffi::{c_char, c_int, c_void};
    pub(super) const TYPE_OTHER: c_int = 0;
    pub(super) const TYPE_LOOPBACK: c_int = 4;
    pub(super) const STATUS_SATISFIED: c_int = 1;
    #[link(name = "Network", kind = "framework")]
    extern "C" {
        pub(super) fn nw_path_monitor_create() -> *mut c_void;
        pub(super) fn nw_path_monitor_prohibit_interface_type(monitor: *mut c_void, kind: c_int);
        pub(super) fn nw_path_monitor_set_queue(
            monitor: *mut c_void,
            queue: &dispatch2::DispatchQueue,
        );
        pub(super) fn nw_path_monitor_set_update_handler(
            monitor: *mut c_void,
            handler: &DynBlock<dyn Fn(*mut c_void)>,
        );
        pub(super) fn nw_path_monitor_start(monitor: *mut c_void);
        pub(super) fn nw_path_monitor_cancel(monitor: *mut c_void);
        pub(super) fn nw_path_get_status(path: *mut c_void) -> c_int;
        pub(super) fn nw_path_enumerate_interfaces(
            path: *mut c_void,
            // C `bool (^)(nw_interface_t)`: objc2's Bool is the C bool here.
            enumerate: &DynBlock<dyn Fn(*mut c_void) -> objc2::runtime::Bool>,
        );
        pub(super) fn nw_interface_get_type(interface: *mut c_void) -> c_int;
        pub(super) fn nw_interface_get_name(interface: *mut c_void) -> *const c_char;
        pub(super) fn nw_interface_get_index(interface: *mut c_void) -> u32;
        pub(super) fn nw_release(object: *mut c_void);
    }
}

/// The interfaces of one reported path, in its order.
///
/// # Safety
/// `path` must be the live `nw_path_t` an update handler was given.
unsafe fn path_interfaces(path: *mut std::ffi::c_void) -> (bool, Vec<PathInterface>) {
    let satisfied = nw::nw_path_get_status(path) == nw::STATUS_SATISFIED;
    let found = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let collected = found.clone();
    let more = objc2::runtime::Bool::new;
    let enumerate = block2::RcBlock::new(move |interface: *mut std::ffi::c_void| {
        if interface.is_null() {
            return more(true);
        }
        // SAFETY: a non-null nw_interface_t, live for this call.
        let name = unsafe { nw::nw_interface_get_name(interface) };
        if name.is_null() {
            return more(true);
        }
        // SAFETY: a NUL-terminated name owned by the live interface.
        let Ok(name) = unsafe { std::ffi::CStr::from_ptr(name) }.to_str() else {
            return more(true);
        };
        let mut found = collected.borrow_mut();
        found.push(PathInterface {
            name: name.to_owned(),
            // SAFETY: as above.
            index: unsafe { nw::nw_interface_get_index(interface) },
            kind: InterfaceKind::from_raw(unsafe { nw::nw_interface_get_type(interface) }),
        });
        // Bounded: a path never lists more than a few interfaces.
        more(found.len() < 32)
    });
    nw::nw_path_enumerate_interfaces(path, &enumerate);
    drop(enumerate);
    let interfaces = found.borrow().clone();
    (satisfied, interfaces)
}

impl PathMonitor {
    /// Start a monitor that feeds `sink` for a relay of family `v6`. None
    /// when Network.framework returned no monitor.
    pub(crate) fn start(sink: Arc<Mutex<Debounce>>, v6: bool) -> Option<Self> {
        let queue = dispatch2::DispatchQueue::new("aegis-ne-path", None);
        // SAFETY: plain Network.framework calls on the monitor created here,
        // which this value owns (+1) until Drop cancels and releases it.
        unsafe {
            let raw = std::ptr::NonNull::new(nw::nw_path_monitor_create())?;
            nw::nw_path_monitor_prohibit_interface_type(raw.as_ptr(), nw::TYPE_OTHER);
            nw::nw_path_monitor_prohibit_interface_type(raw.as_ptr(), nw::TYPE_LOOPBACK);
            nw::nw_path_monitor_set_queue(raw.as_ptr(), &queue);
            let handler = block2::RcBlock::new(move |path: *mut std::ffi::c_void| {
                if path.is_null() {
                    return;
                }
                // SAFETY: the live path this update handler was given.
                let (satisfied, interfaces) = path_interfaces(path);
                // An unreadable address list is no observation at all: an
                // empty one would look like every interface losing its
                // addresses and move a working pin.
                let Ok(addresses) = relay_socket::interface_addresses() else {
                    return;
                };
                let observed = observe(satisfied, &interfaces, v6, &addresses);
                Watch::feed(&sink, observed, Instant::now());
            });
            // The monitor copies the handler block.
            nw::nw_path_monitor_set_update_handler(raw.as_ptr(), &handler);
            nw::nw_path_monitor_start(raw.as_ptr());
            Some(Self { raw, _queue: queue })
        }
    }
}

impl Drop for PathMonitor {
    fn drop(&mut self) {
        // SAFETY: the monitor this value owns; cancelled and released once.
        // A handler already queued only feeds its own coalescer.
        unsafe {
            nw::nw_path_monitor_cancel(self.raw.as_ptr());
            nw::nw_release(self.raw.as_ptr());
        }
    }
}

/// One epoch's path watch and its monitor (absent when none could start).
pub(crate) struct EpochPath {
    pub(crate) watch: Watch,
    _monitor: Option<PathMonitor>,
}

impl EpochPath {
    /// Watch the physical path for a relay of family `v6`.
    pub(crate) fn start(v6: bool) -> Self {
        let watch = Watch::default();
        let monitor = PathMonitor::start(watch.sink(), v6);
        if monitor.is_none() {
            crate::apple::log_code("path_monitor_refused", "create_failed");
        }
        Self {
            watch,
            _monitor: monitor,
        }
    }
}

#[cfg(test)]
#[path = "path_watch_tests.rs"]
mod tests;
