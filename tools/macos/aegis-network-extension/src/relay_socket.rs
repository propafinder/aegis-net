//! B-06 S16f: every provider TCP socket to the relay is bound to the
//! physical interface that reached the relay before the tunnel was up.
//!
//! With `includeAllNetworks` the provider's own full-wide tunnel captures its
//! new sockets as well, so a relay dial made after the network settings were
//! applied loops through the packet engine. As other macOS VPN providers do,
//! the session resolves the relay's egress interface once, before its first
//! dial and before any network settings exist, and binds every relay socket
//! to it with `IP_BOUND_IF` / `IPV6_BOUND_IF` before `connect`. A tunnel
//! (utun, ppp and any other point-to-point interface), IPsec, loopback or
//! Apple peer-to-peer interface is never a relay interface. Path-change
//! rebinding is not part of this step: a socket whose interface vanished
//! fails its connect, and that errno is logged.
use std::{
    ffi::{CStr, CString},
    io, mem,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket},
    os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
};
use tokio::net::{TcpSocket, TcpStream};

/// Stable refusal code of an unresolvable or non-physical relay interface.
pub(crate) const UNRESOLVED: &str = "relay_interface_unresolved";

/// Interface-name prefixes that never carry the relay: tunnels of this or any
/// other VPN (utun, the built-in L2TP/PPTP ppp, legacy tun/tap, gif, stf and
/// ZeroTier feth), IPsec, loopback and Apple peer-to-peer links (awdl, llw).
/// Point-to-point interfaces are refused by flag as well, whatever their name.
const REFUSED_PREFIXES: [&str; 11] = [
    "utun", "ipsec", "lo", "ppp", "tun", "tap", "gif", "stf", "feth", "awdl", "llw",
];

/// The interface every relay socket of one session is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayInterface {
    name: String,
    index: u32,
}

impl RelayInterface {
    pub(crate) fn name(&self) -> &str {
        &self.name
    }

    pub(crate) fn index(&self) -> u32 {
        self.index
    }

    /// S18: the physical interface a path monitor reported, admitted only
    /// when its name may carry the relay and the kernel still gives that
    /// name exactly this index. No route lookup: after the full-wide
    /// settings it would name the tunnel.
    pub(crate) fn physical(name: &str, index: u32) -> Result<Self, &'static str> {
        admit_physical(name, index, name_to_index)
    }
}

/// `RelayInterface::physical` over an injected name-to-index lookup.
pub(crate) fn admit_physical(
    name: &str,
    index: u32,
    lookup: impl FnOnce(&str) -> Option<u32>,
) -> Result<RelayInterface, &'static str> {
    if index == 0 || refused_name(name) || lookup(name) != Some(index) {
        return Err(UNRESOLVED);
    }
    Ok(RelayInterface {
        name: name.to_owned(),
        index,
    })
}

// Test-only overrides.
#[cfg(test)]
impl RelayInterface {
    /// Test-only override: lo0, so loopback test relays can be reached by a
    /// bound socket. Production resolution refuses loopback.
    pub(crate) fn loopback_for_test() -> Self {
        let index = name_to_index("lo0").expect("lo0 has an index");
        Self {
            name: "lo0".into(),
            index,
        }
    }

    /// Test-only: an arbitrary name and index, for refusal tests.
    pub(crate) fn for_test(name: &str, index: u32) -> Self {
        Self {
            name: name.into(),
            index,
        }
    }
}

/// One address of one interface, as getifaddrs reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct InterfaceAddress {
    pub(crate) name: String,
    pub(crate) address: IpAddr,
    pub(crate) up: bool,
    pub(crate) loopback: bool,
    pub(crate) point_to_point: bool,
}

/// Whether `name` may never be a relay interface.
pub(crate) fn refused_name(name: &str) -> bool {
    name.is_empty()
        || REFUSED_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

/// The one physical interface that holds `local`, the source address the
/// kernel chose for the relay. Refused: an unspecified or loopback source, no
/// interface or several differently named interfaces holding it, and an
/// interface that is down, loopback, point-to-point, or named as a tunnel,
/// IPsec, loopback or peer-to-peer link.
pub(crate) fn select_interface(
    local: IpAddr,
    interfaces: &[InterfaceAddress],
) -> Result<&str, &'static str> {
    if local.is_unspecified() || local.is_loopback() {
        return Err(UNRESOLVED);
    }
    let mut holders = interfaces.iter().filter(|entry| entry.address == local);
    let chosen = holders.next().ok_or(UNRESOLVED)?;
    if holders.any(|other| other.name != chosen.name) {
        return Err(UNRESOLVED);
    }
    if !chosen.up || chosen.loopback || chosen.point_to_point || refused_name(&chosen.name) {
        return Err(UNRESOLVED);
    }
    Ok(&chosen.name)
}

fn name_to_index(name: &str) -> Option<u32> {
    let name = CString::new(name).ok()?;
    // SAFETY: `name` is a valid NUL-terminated string for the call.
    match unsafe { libc::if_nametoindex(name.as_ptr()) } {
        0 => None,
        index => Some(index),
    }
}

/// The interface the session's relay sockets are bound to: the source
/// address of a connected (never sending) UDP socket to `relay`, the one
/// interface holding it, and its index. Run before the first dial and before
/// any network settings are applied.
pub(crate) fn resolve_relay_interface(relay: SocketAddr) -> Result<RelayInterface, &'static str> {
    let local = route_source(relay).map_err(|_| UNRESOLVED)?;
    let interfaces = interface_addresses().map_err(|_| UNRESOLVED)?;
    let name = select_interface(local, &interfaces)?.to_owned();
    let index = name_to_index(&name).ok_or(UNRESOLVED)?;
    Ok(RelayInterface { name, index })
}

fn sockaddr_of(address: SocketAddr) -> (libc::sockaddr_storage, libc::socklen_t) {
    // SAFETY: an all-zero sockaddr_storage is a valid value.
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let length = match address {
        SocketAddr::V4(v4) => {
            let raw = libc::sockaddr_in {
                sin_len: mem::size_of::<libc::sockaddr_in>() as u8,
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: v4.port().to_be(),
                sin_addr: libc::in_addr {
                    s_addr: u32::from(*v4.ip()).to_be(),
                },
                sin_zero: [0; 8],
            };
            // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_in.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw) };
            mem::size_of::<libc::sockaddr_in>()
        }
        SocketAddr::V6(v6) => {
            let raw = libc::sockaddr_in6 {
                sin6_len: mem::size_of::<libc::sockaddr_in6>() as u8,
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: v6.port().to_be(),
                sin6_flowinfo: v6.flowinfo(),
                sin6_addr: libc::in6_addr {
                    s6_addr: v6.ip().octets(),
                },
                sin6_scope_id: v6.scope_id(),
            };
            // SAFETY: sockaddr_storage is larger than and aligned for sockaddr_in6.
            unsafe { std::ptr::write((&mut storage as *mut libc::sockaddr_storage).cast(), raw) };
            mem::size_of::<libc::sockaddr_in6>()
        }
    };
    (storage, length as libc::socklen_t)
}

/// The IP address of a sockaddr of family AF_INET or AF_INET6.
///
/// # Safety
/// `address` must point to a valid sockaddr of at least its family's size.
unsafe fn ip_of(address: *const libc::sockaddr) -> Option<IpAddr> {
    match i32::from((*address).sa_family) {
        libc::AF_INET => {
            let v4 = &*address.cast::<libc::sockaddr_in>();
            Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
        }
        libc::AF_INET6 => {
            let v6 = &*address.cast::<libc::sockaddr_in6>();
            Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

/// The source address the kernel routes `relay` from. The UDP socket is
/// connected, so the kernel binds it to that one address; nothing is sent and
/// no unspecified address is bound.
fn route_source(relay: SocketAddr) -> io::Result<IpAddr> {
    route_source_on_interface(relay, None)
}

/// A source-only UDP probe for a signed numeric peer. `connect` selects the
/// kernel route and local address without sending a datagram. The interface
/// restriction precedes connect, and this probe is closed before the final
/// unconnected Quinn socket is created.
fn route_source_on_interface(
    relay: SocketAddr,
    interface: Option<&RelayInterface>,
) -> io::Result<IpAddr> {
    let family = if relay.is_ipv4() {
        libc::AF_INET
    } else {
        libc::AF_INET6
    };
    // SAFETY: plain socket(2); the descriptor is owned at once.
    let fd = unsafe { libc::socket(family, libc::SOCK_DGRAM, libc::IPPROTO_UDP) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a new descriptor owned by nothing else.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    if let Some(interface) = interface {
        if name_to_index(interface.name()) != Some(interface.index()) {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        bind_fd(socket.as_raw_fd(), relay.is_ipv6(), interface.index())?;
        if bound_index(socket.as_raw_fd(), relay.is_ipv6())? != interface.index() {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let wildcard = if relay.is_ipv6() {
            SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0)
        } else {
            SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0)
        };
        let (local, local_length) = sockaddr_of(wildcard);
        // SAFETY: the wildcard address has the socket's family and exact
        // sockaddr length. This allocates an ephemeral port but sends nothing.
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&local as *const libc::sockaddr_storage).cast(),
                local_length,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    let (peer, length) = sockaddr_of(relay);
    // SAFETY: `peer` holds a valid sockaddr of `length` bytes.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&peer as *const libc::sockaddr_storage).cast(),
            length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: an all-zero sockaddr_storage is a valid value.
    let mut local: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut local_length = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    // SAFETY: `local` has room for `local_length` bytes.
    if unsafe {
        libc::getsockname(
            socket.as_raw_fd(),
            (&mut local as *mut libc::sockaddr_storage).cast(),
            &mut local_length,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getsockname wrote a sockaddr of the socket's own family.
    unsafe { ip_of((&local as *const libc::sockaddr_storage).cast()) }
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

/// Admit the kernel-selected address on exactly the saved physical interface.
/// Several different IPv6 addresses on that interface are normal; only the
/// one selected for this signed peer is used. A duplicated source on another
/// interface or a stale/down/tunnel holder still fails closed.
pub(crate) fn select_bound_udp_source(
    source: IpAddr,
    peer: SocketAddr,
    interface: &RelayInterface,
    addresses: &[InterfaceAddress],
) -> io::Result<IpAddr> {
    let test_loopback = cfg!(test) && interface.name() == "lo0";
    if source.is_unspecified()
        || source.is_multicast()
        || (source.is_loopback() && !test_loopback)
        || source.is_ipv4() != peer.is_ipv4()
        || peer.port() == 0
        || peer.ip().is_unspecified()
        || peer.ip().is_multicast()
        || (refused_name(interface.name()) && !test_loopback)
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let mut found = false;
    for entry in addresses.iter().filter(|entry| entry.address == source) {
        if entry.name != interface.name()
            || !entry.up
            || (entry.loopback && !test_loopback)
            || entry.point_to_point
        {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        found = true;
    }
    if !found {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(source)
}

/// Learn the kernel-selected physical source for one exact signed peer. The
/// interface-bound probe sends no datagrams and is closed before returning.
pub(crate) fn physical_source_for_peer(
    peer: SocketAddr,
    interface: &RelayInterface,
) -> io::Result<IpAddr> {
    if peer.port() == 0 || peer.ip().is_unspecified() || peer.ip().is_multicast() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let source = route_source_on_interface(peer, Some(interface))?;
    select_bound_udp_source(source, peer, interface, &interface_addresses()?)?;
    if name_to_index(interface.name()) != Some(interface.index()) {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(source)
}

/// Create a fresh, interface-bound, unconnected UDP socket for the exact peer.
/// The connected probe is never reused as a transport or disconnected with
/// AF_UNSPEC. Neither the probe nor the returned socket sends application data.
pub(crate) fn bound_udp_socket(
    peer: SocketAddr,
    interface: &RelayInterface,
) -> io::Result<UdpSocket> {
    let source = physical_source_for_peer(peer, interface)?;
    let socket = UdpSocket::bind(SocketAddr::new(source, 0))?;
    bind_ice_udp(&socket, interface, source)?;
    if !socket
        .peer_addr()
        .is_err_and(|error| error.kind() == io::ErrorKind::NotConnected)
        || socket.local_addr()?.ip() != source
        || bound_index(socket.as_raw_fd(), peer.is_ipv6())? != interface.index()
        || name_to_index(interface.name()) != Some(interface.index())
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    select_bound_udp_source(source, peer, interface, &interface_addresses()?)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

/// Every IPv4 and IPv6 address of every interface, from getifaddrs.
pub(crate) fn interface_addresses() -> io::Result<Vec<InterfaceAddress>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: getifaddrs writes a list head that freeifaddrs releases below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut found = Vec::new();
    let mut cursor = head;
    while !cursor.is_null() {
        // SAFETY: `cursor` is a node of the list getifaddrs returned.
        let entry = unsafe { &*cursor };
        cursor = entry.ifa_next;
        if entry.ifa_addr.is_null() || entry.ifa_name.is_null() {
            continue;
        }
        // SAFETY: a non-null ifa_addr is a sockaddr of its own family.
        let Some(address) = (unsafe { ip_of(entry.ifa_addr) }) else {
            continue;
        };
        // SAFETY: ifa_name is a NUL-terminated interface name.
        let name = unsafe { CStr::from_ptr(entry.ifa_name) };
        let Ok(name) = name.to_str() else {
            continue;
        };
        let flags = entry.ifa_flags as libc::c_int;
        found.push(InterfaceAddress {
            name: name.to_owned(),
            address,
            up: flags & libc::IFF_UP != 0,
            loopback: flags & libc::IFF_LOOPBACK != 0,
            point_to_point: flags & libc::IFF_POINTOPOINT != 0,
        });
    }
    // SAFETY: `head` came from getifaddrs and is freed exactly once.
    unsafe { libc::freeifaddrs(head) };
    Ok(found)
}

fn bound_option(ipv6: bool) -> (libc::c_int, libc::c_int) {
    if ipv6 {
        (libc::IPPROTO_IPV6, libc::IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, libc::IP_BOUND_IF)
    }
}

/// Bind `fd` to interface `index`. Index 0 would clear the binding, so it is
/// refused.
fn bind_fd(fd: RawFd, ipv6: bool, index: u32) -> io::Result<()> {
    if index == 0 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let (level, option) = bound_option(ipv6);
    let value = libc::c_uint::from(index);
    // SAFETY: `value` is a c_uint of the length passed, as the option takes.
    let result = unsafe {
        libc::setsockopt(
            fd,
            level,
            option,
            (&value as *const libc::c_uint).cast(),
            mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The interface index `fd` is bound to (0: unbound).
pub(crate) fn bound_index(fd: RawFd, ipv6: bool) -> io::Result<u32> {
    let (level, option) = bound_option(ipv6);
    let mut value: libc::c_uint = 0;
    let mut length = mem::size_of::<libc::c_uint>() as libc::socklen_t;
    // SAFETY: `value` has room for `length` bytes.
    let result = unsafe {
        libc::getsockopt(
            fd,
            level,
            option,
            (&mut value as *mut libc::c_uint).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// D6's ICE backend creates each UDP socket before handing it to its runtime.
/// This callback runs at that handoff, including an ICE restart, before the
/// reactor can send. It accepts only the saved physical source and index;
/// all remote tuples still need a separate exact-candidate filter owner.
#[allow(dead_code)] // D6 profile admission awaits the composite media owner.
pub(crate) fn bind_ice_udp(
    socket: &UdpSocket,
    interface: &RelayInterface,
    expected_source: IpAddr,
) -> io::Result<()> {
    let local = socket.local_addr()?;
    if local.port() == 0
        || local.ip() != expected_source
        || expected_source.is_unspecified()
        || name_to_index(interface.name()) != Some(interface.index())
    {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    let ipv6 = local.is_ipv6();
    bind_fd(socket.as_raw_fd(), ipv6, interface.index())?;
    if bound_index(socket.as_raw_fd(), ipv6)? != interface.index() {
        return Err(io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

/// A TCP socket of `relay`'s family bound to `interface`, not yet connected.
pub(crate) fn bound_socket(relay: SocketAddr, interface: &RelayInterface) -> io::Result<TcpSocket> {
    let socket = if relay.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    bind_fd(socket.as_raw_fd(), relay.is_ipv6(), interface.index)?;
    Ok(socket)
}

/// Whether a connect error means the bound interface is gone.
pub(crate) fn interface_lost(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(libc::ENETDOWN | libc::EADDRNOTAVAIL | libc::ENXIO)
    )
}

/// The only way the provider dials its relay: a socket bound to the
/// session's relay interface before connect. Callers keep their own
/// timeouts. A bind or connect refused because the interface vanished logs
/// its errno; a path change re-pins the epoch and rebuilds (S18).
pub(crate) async fn connect_bound(
    relay: SocketAddr,
    interface: &RelayInterface,
) -> io::Result<TcpStream> {
    let connected = match bound_socket(relay, interface) {
        Ok(socket) => socket.connect(relay).await,
        Err(error) => Err(error),
    };
    connected.inspect_err(|error| {
        if interface_lost(error) {
            if let Some(errno) = error.raw_os_error() {
                crate::apple::log_code("relay_interface_lost", &format!("errno:{errno}"));
            }
        }
    })
}

/// Installed diagnosis: the resolved relay interface's name.
pub(crate) fn log_interface(interface: &RelayInterface) {
    crate::apple::log_code("relay_interface", &format!("name:{}", interface.name));
}

#[cfg(test)]
#[path = "relay_socket_tests.rs"]
mod tests;
