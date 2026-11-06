//! B-06 v40 (CP-D3 M1): the access network key of the carrier failover
//! memory on macOS.
//!
//! aegis-core's controller keeps its breakers per access network
//! (`NetworkKey`), so a carrier blocked on one network is not avoided on
//! another. The Linux client derives the key from its default route; here a
//! Network.framework path monitor of the provider process (physical
//! interface types only: the tunnel's `other` and loopback are prohibited,
//! as the S18 path watch's are) reports the path's preferred eligible
//! interface (its type and BSD name) and the path's gateways
//! (`nw_path_enumerate_gateways`). They are hashed with a random salt of
//! this process into a 16-byte key ([`derive`]); nothing reversible is
//! kept, nothing is written anywhere and nothing is logged but the key's
//! four-byte label. Before the first report, and on a path with no eligible
//! interface, the key is `NetworkKey::UNKNOWN`, which every such session
//! shares.
use crate::path_watch::{eligible, InterfaceKind, PathInterface};
use aegis_core::brain::carrier_failover::NetworkKey;
use std::{
    net::IpAddr,
    sync::{Mutex, OnceLock, PoisonError},
};

/// The latest key the process's path monitor derived.
static CURRENT: Mutex<Option<NetworkKey>> = Mutex::new(None);

/// This process's salt: 32 random bytes, never stored.
fn salt() -> &'static [u8; 32] {
    static SALT: OnceLock<[u8; 32]> = OnceLock::new();
    SALT.get_or_init(|| {
        let mut salt = [0u8; 32];
        // SAFETY: writes exactly `salt.len()` bytes into the owned buffer.
        unsafe { libc::arc4random_buf(salt.as_mut_ptr().cast(), salt.len()) };
        salt
    })
}

fn kind_code(kind: InterfaceKind) -> u8 {
    match kind {
        InterfaceKind::Other => 0,
        InterfaceKind::Wifi => 1,
        InterfaceKind::Cellular => 2,
        InterfaceKind::Wired => 3,
        InterfaceKind::Loopback => 4,
    }
}

/// The key of a network reached over an interface of `kind` named `name`
/// whose gateways are `gateways` (order and repeats do not matter).
pub(crate) fn derive(
    salt: &[u8; 32],
    kind: InterfaceKind,
    name: &str,
    gateways: &[IpAddr],
) -> NetworkKey {
    let mut gateways: Vec<IpAddr> = gateways.to_vec();
    gateways.sort();
    gateways.dedup();
    let mut octets = Vec::with_capacity(gateways.len() * 17);
    for gateway in &gateways {
        match gateway {
            IpAddr::V4(v4) => {
                octets.push(4);
                octets.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                octets.push(6);
                octets.extend_from_slice(&v6.octets());
            }
        }
    }
    let kind = [kind_code(kind)];
    let parts: [&[u8]; 4] = [b"macos-path", &kind, name.as_bytes(), &octets];
    NetworkKey::derive(salt, &parts)
}

/// The key of one reported path: its preferred eligible interface (the
/// first, in the path's order) and its gateways; `UNKNOWN` when the path is
/// unsatisfied or has no eligible interface.
pub(crate) fn path_key(
    salt: &[u8; 32],
    satisfied: bool,
    interfaces: &[PathInterface],
    gateways: &[IpAddr],
) -> NetworkKey {
    if !satisfied {
        return NetworkKey::UNKNOWN;
    }
    match interfaces.iter().find(|interface| eligible(interface)) {
        Some(interface) => derive(salt, interface.kind, &interface.name, gateways),
        None => NetworkKey::UNKNOWN,
    }
}

/// The current access network's key: the path monitor's latest, else
/// `UNKNOWN`.
pub(crate) fn current() -> NetworkKey {
    CURRENT
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .unwrap_or(NetworkKey::UNKNOWN)
}

fn publish(key: NetworkKey) {
    let changed = {
        let mut current = CURRENT.lock().unwrap_or_else(PoisonError::into_inner);
        let changed = *current != Some(key);
        *current = Some(key);
        changed
    };
    if changed {
        crate::apple::log_code("carrier_network", &format!("net:{}", key.label()));
    }
}

mod nw {
    use block2::DynBlock;
    use std::ffi::{c_int, c_void};
    pub(super) const TYPE_OTHER: c_int = 0;
    pub(super) const TYPE_LOOPBACK: c_int = 4;
    pub(super) const STATUS_SATISFIED: c_int = 1;
    pub(super) const ENDPOINT_ADDRESS: c_int = 1;
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
        pub(super) fn nw_path_get_status(path: *mut c_void) -> c_int;
        pub(super) fn nw_path_enumerate_interfaces(
            path: *mut c_void,
            enumerate: &DynBlock<dyn Fn(*mut c_void) -> objc2::runtime::Bool>,
        );
        pub(super) fn nw_path_enumerate_gateways(
            path: *mut c_void,
            enumerate: &DynBlock<dyn Fn(*mut c_void) -> objc2::runtime::Bool>,
        );
        pub(super) fn nw_interface_get_type(interface: *mut c_void) -> c_int;
        pub(super) fn nw_interface_get_name(interface: *mut c_void) -> *const std::ffi::c_char;
        pub(super) fn nw_interface_get_index(interface: *mut c_void) -> u32;
        pub(super) fn nw_endpoint_get_type(endpoint: *mut c_void) -> c_int;
        pub(super) fn nw_endpoint_get_address(endpoint: *mut c_void) -> *const libc::sockaddr;
    }
}

/// The address of one `sockaddr`, if it is IPv4 or IPv6.
///
/// # Safety
/// `address` must be null or point to a valid `sockaddr` of its family's
/// full size.
unsafe fn socket_ip(address: *const libc::sockaddr) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    match i32::from((*address).sa_family) {
        libc::AF_INET => {
            let v4 = &*address.cast::<libc::sockaddr_in>();
            Some(IpAddr::from(u32::from_be(v4.sin_addr.s_addr).to_be_bytes()))
        }
        libc::AF_INET6 => {
            let v6 = &*address.cast::<libc::sockaddr_in6>();
            Some(IpAddr::from(v6.sin6_addr.s6_addr))
        }
        _ => None,
    }
}

/// The interfaces and gateways of one reported path, bounded.
///
/// # Safety
/// `path` must be the live `nw_path_t` an update handler was given.
unsafe fn path_facts(path: *mut std::ffi::c_void) -> (bool, Vec<PathInterface>, Vec<IpAddr>) {
    use std::{cell::RefCell, rc::Rc};
    let satisfied = nw::nw_path_get_status(path) == nw::STATUS_SATISFIED;
    let more = objc2::runtime::Bool::new;
    let interfaces = Rc::new(RefCell::new(Vec::new()));
    let collected = interfaces.clone();
    let enumerate = block2::RcBlock::new(move |interface: *mut std::ffi::c_void| {
        if interface.is_null() {
            return more(true);
        }
        // SAFETY: a non-null nw_interface_t, live for this call; its name is
        // NUL-terminated and owned by it.
        let name = unsafe { nw::nw_interface_get_name(interface) };
        if name.is_null() {
            return more(true);
        }
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
        more(found.len() < 32)
    });
    nw::nw_path_enumerate_interfaces(path, &enumerate);
    drop(enumerate);
    let gateways = Rc::new(RefCell::new(Vec::new()));
    let collected = gateways.clone();
    let enumerate = block2::RcBlock::new(move |endpoint: *mut std::ffi::c_void| {
        if endpoint.is_null() {
            return more(true);
        }
        // SAFETY: a non-null nw_endpoint_t, live for this call; an address
        // endpoint's sockaddr is owned by it and sized for its family.
        if unsafe { nw::nw_endpoint_get_type(endpoint) } == nw::ENDPOINT_ADDRESS {
            if let Some(ip) = unsafe { socket_ip(nw::nw_endpoint_get_address(endpoint)) } {
                let mut found = collected.borrow_mut();
                found.push(ip);
                return more(found.len() < 16);
            }
        }
        more(true)
    });
    nw::nw_path_enumerate_gateways(path, &enumerate);
    drop(enumerate);
    let interfaces = interfaces.borrow().clone();
    let gateways = gateways.borrow().clone();
    (satisfied, interfaces, gateways)
}

/// The process's path monitor: started once, by the first provider start,
/// and kept for the life of the process (its queue feeds only [`CURRENT`]).
struct KeyMonitor {
    _raw: std::ptr::NonNull<std::ffi::c_void>,
    _queue: dispatch2::DispatchRetained<dispatch2::DispatchQueue>,
}
// SAFETY: the monitor and its queue are only retained here; Network.framework
// objects are thread-safe to retain and the handler runs on its own queue.
unsafe impl Send for KeyMonitor {}
unsafe impl Sync for KeyMonitor {}

static MONITOR: OnceLock<Option<KeyMonitor>> = OnceLock::new();

/// Start the process's network key monitor once (idempotent). A monitor
/// Network.framework refuses leaves the key `UNKNOWN`.
pub(crate) fn start() {
    MONITOR.get_or_init(|| {
        let queue = dispatch2::DispatchQueue::new("aegis-ne-carrier-network", None);
        // SAFETY: plain Network.framework calls on the monitor created here,
        // which `KeyMonitor` owns (+1) for the life of the process.
        let monitor = unsafe {
            let raw = std::ptr::NonNull::new(nw::nw_path_monitor_create())?;
            nw::nw_path_monitor_prohibit_interface_type(raw.as_ptr(), nw::TYPE_OTHER);
            nw::nw_path_monitor_prohibit_interface_type(raw.as_ptr(), nw::TYPE_LOOPBACK);
            nw::nw_path_monitor_set_queue(raw.as_ptr(), &queue);
            let handler = block2::RcBlock::new(move |path: *mut std::ffi::c_void| {
                if path.is_null() {
                    return;
                }
                // SAFETY: the live path this update handler was given.
                let (satisfied, interfaces, gateways) = path_facts(path);
                publish(path_key(salt(), satisfied, &interfaces, &gateways));
            });
            // The monitor copies the handler block.
            nw::nw_path_monitor_set_update_handler(raw.as_ptr(), &handler);
            nw::nw_path_monitor_start(raw.as_ptr());
            raw
        };
        Some(KeyMonitor {
            _raw: monitor,
            _queue: queue,
        })
    });
    if MONITOR.get().is_some_and(Option::is_none) {
        crate::apple::log_code("carrier_network", "monitor_refused");
    }
}

#[cfg(test)]
#[path = "carrier_network_tests.rs"]
mod tests;
