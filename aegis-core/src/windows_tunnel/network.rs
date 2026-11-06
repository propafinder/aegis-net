//! IP Helper configuration with exact ownership of added routes. Physical
//! adapters, their default routes and their DNS configuration are never edited.
use crate::tunnel_policy::{Prefix, ANCHOR_V4, CLIENT_V4, CLIENT_V6};
use serde::{Deserialize, Serialize};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    ptr,
};
use windows_sys::Win32::{
    NetworkManagement::{IpHelper::*, Ndis::*},
    Networking::WinSock::*,
};

fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}
pub fn sockaddr(address: IpAddr) -> SOCKADDR_INET {
    let mut result = SOCKADDR_INET::default();
    match address {
        IpAddr::V4(ip) => {
            result.Ipv4.sin_family = AF_INET;
            result.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
        }
        IpAddr::V6(ip) => {
            result.Ipv6.sin6_family = AF_INET6;
            result.Ipv6.sin6_addr.u.Byte = ip.octets();
        }
    }
    result
}
fn address(value: SOCKADDR_INET) -> IpAddr {
    unsafe {
        if value.si_family == AF_INET {
            Ipv4Addr::from(value.Ipv4.sin_addr.S_un.S_addr.to_ne_bytes()).into()
        } else {
            Ipv6Addr::from(value.Ipv6.sin6_addr.u.Byte).into()
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub luid: u64,
    pub index: u32,
    pub prefix: Prefix,
    pub next_hop: IpAddr,
    pub scope_id: u32,
    pub metric: u32,
}
impl Route {
    pub fn exists(&self) -> io::Result<bool> {
        let code = unsafe { GetIpForwardEntry2(&mut self.row()) };
        if code == 0 {
            Ok(true)
        } else if code == 1168 || code == 2 {
            Ok(false)
        } else {
            check(code).map(|_| false)
        }
    }
    fn row(&self) -> MIB_IPFORWARD_ROW2 {
        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceLuid = NET_LUID_LH { Value: self.luid };
        row.InterfaceIndex = self.index;
        row.DestinationPrefix = IP_ADDRESS_PREFIX {
            Prefix: sockaddr(self.prefix.address),
            PrefixLength: self.prefix.length,
        };
        row.NextHop = sockaddr(self.next_hop);
        if self.next_hop.is_ipv6() {
            row.NextHop.Ipv6.Anonymous.sin6_scope_id = self.scope_id;
        }
        row.Metric = self.metric;
        row.Protocol = MIB_IPPROTO_NETMGMT;
        row.ValidLifetime = u32::MAX;
        row.PreferredLifetime = u32::MAX;
        row
    }
    pub fn remove(&self) -> io::Result<()> {
        let code = unsafe { DeleteIpForwardEntry2(&self.row()) };
        if code == 1168 || code == 2 {
            Ok(())
        } else {
            check(code)
        }
    }
}
/// Snapshot a relay endpoint's native path BEFORE capture routes are applied.
pub fn native_route(ip: IpAddr) -> io::Result<Route> {
    let mut row = MIB_IPFORWARD_ROW2::default();
    let mut source = SOCKADDR_INET::default();
    check(unsafe {
        GetBestRoute2(
            ptr::null(),
            0,
            ptr::null(),
            &sockaddr(ip),
            0,
            &mut row,
            &mut source,
        )
    })?;
    Ok(Route {
        luid: unsafe { row.InterfaceLuid.Value },
        index: row.InterfaceIndex,
        prefix: Prefix {
            address: ip,
            length: if ip.is_ipv4() { 32 } else { 128 },
        },
        next_hop: address(row.NextHop),
        scope_id: if ip.is_ipv6() {
            unsafe { row.NextHop.Ipv6.Anonymous.sin6_scope_id }
        } else {
            0
        },
        metric: 0,
    })
}
/// Stable physical default-route fingerprint. Lifetimes do not matter; a
/// gateway/interface/metric change requires rebuilding the pinned relay path.
pub fn default_route_signature(tunnel_luid: u64) -> io::Result<Vec<(u64, String, u32)>> {
    let mut table = ptr::null_mut();
    check(unsafe { GetIpForwardTable2(AF_UNSPEC, &mut table) })?;
    struct Table(*mut MIB_IPFORWARD_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            unsafe {
                FreeMibTable(self.0.cast());
            }
        }
    }
    let table = Table(table);
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > 8192 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let rows = unsafe { std::slice::from_raw_parts((*table.0).Table.as_ptr(), count) };
    let mut result = vec![];
    for row in rows {
        let luid = unsafe { row.InterfaceLuid.Value };
        if luid != tunnel_luid && row.DestinationPrefix.PrefixLength == 0 {
            result.push((luid, address(row.NextHop).to_string(), row.Metric));
        }
    }
    result.sort();
    Ok(result)
}
pub fn adapter_luid(name: &str) -> io::Result<u64> {
    let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
    let mut luid = NET_LUID_LH { Value: 0 };
    check(unsafe { ConvertInterfaceAliasToLuid(name.as_ptr(), &mut luid) })?;
    Ok(unsafe { luid.Value })
}
pub struct NetworkGuard {
    pub routes: Vec<Route>,
    pub luid: u64,
    pub index: u32,
    cleanup_on_drop: bool,
}
impl NetworkGuard {
    /// Owns routes on an existing adapter without changing its address or DNS
    /// configuration. Routes added through this guard are removed on drop.
    pub fn route_only(luid: u64) -> io::Result<Self> {
        let value = NET_LUID_LH { Value: luid };
        let mut index = 0;
        check(unsafe { ConvertInterfaceLuidToIndex(&value, &mut index) })?;
        Ok(Self {
            routes: vec![],
            luid,
            index,
            cleanup_on_drop: true,
        })
    }
    pub fn configure(luid: u64, mtu: u32, dns: bool) -> io::Result<Self> {
        let value = NET_LUID_LH { Value: luid };
        let guard = Self::route_only(luid)?;
        for ip in [IpAddr::V4(CLIENT_V4), IpAddr::V6(CLIENT_V6)] {
            let mut row = MIB_UNICASTIPADDRESS_ROW::default();
            unsafe { InitializeUnicastIpAddressEntry(&mut row) };
            row.Address = sockaddr(ip);
            row.InterfaceLuid = value;
            row.OnLinkPrefixLength = if ip.is_ipv4() { 32 } else { 128 };
            row.DadState = IpDadStatePreferred;
            row.ValidLifetime = u32::MAX;
            row.PreferredLifetime = u32::MAX;
            let mut interface = MIB_IPINTERFACE_ROW::default();
            unsafe { InitializeIpInterfaceEntry(&mut interface) };
            interface.Family = if ip.is_ipv4() { AF_INET } else { AF_INET6 };
            interface.InterfaceLuid = value;
            check(unsafe { GetIpInterfaceEntry(&mut interface) })?;
            interface.NlMtu = mtu;
            interface.UseAutomaticMetric = false;
            interface.Metric = 0;
            interface.DadTransmits = 0;
            interface.SitePrefixLength = 0;
            interface.RouterDiscoveryBehavior = RouterDiscoveryDisabled;
            check(unsafe { SetIpInterfaceEntry(&mut interface) })?;
            check(unsafe { CreateUnicastIpAddressEntry(&row) })?;
            // Creation is not a readiness guarantee. Configure DAD before
            // adding addresses and query actual state before publishing routes
            // or SCM readiness and accepting the first DNS packet.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                check(unsafe { GetUnicastIpAddressEntry(&mut row) })?;
                if row.DadState == IpDadStatePreferred {
                    break;
                }
                if row.DadState != IpDadStateTentative {
                    return Err(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "tunnel address is not usable",
                    ));
                }
                if std::time::Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "tunnel address readiness timed out",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
        }
        if dns {
            let mut guid = windows_sys::core::GUID::from_u128(0);
            check(unsafe { ConvertInterfaceLuidToGuid(&value, &mut guid) })?;
            let mut names: Vec<u16> = ANCHOR_V4
                .to_string()
                .encode_utf16()
                .chain(Some(0))
                .collect();
            let settings = DNS_INTERFACE_SETTINGS {
                Version: DNS_INTERFACE_SETTINGS_VERSION1,
                Flags: (DNS_SETTING_NAMESERVER
                    | DNS_SETTING_REGISTRATION_ENABLED
                    | DNS_SETTINGS_ENABLE_LLMNR) as u64,
                NameServer: names.as_mut_ptr(),
                RegistrationEnabled: 0,
                EnableLLMNR: 0,
                ..Default::default()
            };
            check(unsafe { SetInterfaceDnsSettings(guid, &settings) })?;
        }
        Ok(guard)
    }
    pub fn add(&mut self, route: Route) -> io::Result<()> {
        // The durable journal is written before this call and will remove the
        // route during recovery. Even an identical pre-existing row cannot be
        // adopted: recovery would otherwise delete somebody else's route.
        let mut existing = route.row();
        match unsafe { GetIpForwardEntry2(&mut existing) } {
            0 => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "capture route already exists; refusing to adopt it",
                ));
            }
            1168 | 2 => {}
            code => return Err(io::Error::from_raw_os_error(code as i32)),
        }
        check(unsafe { CreateIpForwardEntry2(&route.row()) })?;
        self.routes.push(route);
        Ok(())
    }
    pub fn capture(&mut self, prefix: Prefix) -> io::Result<()> {
        let next_hop = if prefix.address.is_ipv4() {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        } else {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        };
        self.add(Route {
            luid: self.luid,
            index: self.index,
            prefix,
            next_hop,
            scope_id: 0,
            metric: 0,
        })
    }
    pub fn cleanup(&mut self) -> io::Result<()> {
        let mut error = None;
        let mut pending = vec![];
        for route in self.routes.drain(..).rev() {
            if let Err(e) = route.remove() {
                error = Some(e);
                pending.push(route);
            }
        }
        self.routes = pending;
        error.map_or(Ok(()), Err)
    }
    /// Once a durable route journal is prepared, only its sequenced recovery
    /// may remove routes. A destructor cannot update the journal first.
    pub fn handoff_cleanup_to_journal(&mut self) {
        self.cleanup_on_drop = false;
    }
}
impl Drop for NetworkGuard {
    fn drop(&mut self) {
        if self.cleanup_on_drop {
            let _ = self.cleanup();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_sockaddr_roundtrips_both_families() {
        for ip in ["1.2.3.4", "2001:db8::1234"] {
            let ip: IpAddr = ip.parse().unwrap();
            assert_eq!(address(sockaddr(ip)), ip);
        }
    }
    #[test]
    #[ignore = "requires administrator and AEGIS_TEST_WINTUN; creates only an isolated adapter and two documentation host routes"]
    fn signed_adapter_routes_and_cleanup() {
        let driver = std::env::var_os("AEGIS_TEST_WINTUN").expect("verified driver path");
        let name = format!("AEGIS-Test-{}", std::process::id());
        let mut tun =
            super::super::wintun::Wintun::open(std::path::Path::new(&driver), &name).unwrap();
        let luid = tun.luid;
        // Exercise the native resolver API on this disposable adapter only.
        let mut network = NetworkGuard::configure(luid, 1280, true).unwrap();
        for value in ["192.0.2.123/32", "2001:db8::123/128"] {
            network.capture(Prefix::parse(value).unwrap()).unwrap();
        }
        assert_eq!(network.routes.len(), 2);
        let socket = std::net::UdpSocket::bind((CLIENT_V4, 0)).unwrap();
        socket
            .send_to(b"synthetic native capture", ("192.0.2.123", 12345))
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            if let Some(packet) = tun.receive().unwrap() {
                if packet[0] >> 4 == 4 && packet.ends_with(b"synthetic native capture") {
                    break;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "packet never reached signed adapter"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let routes = network.routes.clone();
        network.cleanup().unwrap();
        network.cleanup().unwrap();
        for route in routes {
            assert_ne!(unsafe { GetIpForwardEntry2(&mut route.row()) }, 0);
        }
        drop(network);
        drop(tun);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let mut index = 0;
            if unsafe { ConvertInterfaceLuidToIndex(&NET_LUID_LH { Value: luid }, &mut index) } != 0
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "adapter removal did not complete"
            );
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}
