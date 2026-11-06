//! Platform-neutral validation of Windows system-tunnel intent.
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WindowsTunnelSettings {
    pub adapter_name: String,
    pub driver: PathBuf,
    /// Empty means both complete address families. A nonempty list is an
    /// explicit split tunnel and must never be reported as full protection.
    pub include_routes: Vec<String>,
    pub dns_upstream: SocketAddr,
    pub configure_dns: bool,
    pub kill_switch: bool,
    pub max_flows: usize,
    pub idle_timeout_secs: u64,
    pub mtu: u32,
}
impl Default for WindowsTunnelSettings {
    fn default() -> Self {
        Self {
            adapter_name: "AEGIS".into(),
            driver: "wintun.dll".into(),
            include_routes: vec![],
            dns_upstream: "9.9.9.9:53".parse().unwrap(),
            configure_dns: true,
            kill_switch: true,
            max_flows: 256,
            idle_timeout_secs: 60,
            mtu: 1280,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prefix {
    pub address: IpAddr,
    pub length: u8,
}
impl Prefix {
    pub fn parse(value: &str) -> Result<Self, String> {
        let (address, length) = value.split_once('/').ok_or("route requires a prefix")?;
        let address: IpAddr = address.parse().map_err(|_| "invalid route address")?;
        let length: u8 = length.parse().map_err(|_| "invalid prefix length")?;
        let valid = match address {
            IpAddr::V4(ip) if length <= 32 => {
                u32::from(ip) & (u32::MAX.checked_shr(length.into()).unwrap_or(0)) == 0
            }
            IpAddr::V6(ip) if length <= 128 => {
                u128::from(ip) & (u128::MAX.checked_shr(length.into()).unwrap_or(0)) == 0
            }
            _ => false,
        };
        if !valid {
            return Err("route must use a canonical network prefix".into());
        }
        Ok(Self { address, length })
    }
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.address, address) {
            (IpAddr::V4(a), IpAddr::V4(b)) => {
                let mask = u32::MAX.checked_shl((32 - self.length).into()).unwrap_or(0);
                u32::from(a) & mask == u32::from(b) & mask
            }
            (IpAddr::V6(a), IpAddr::V6(b)) => {
                let mask = u128::MAX
                    .checked_shl((128 - self.length).into())
                    .unwrap_or(0);
                u128::from(a) & mask == u128::from(b) & mask
            }
            _ => false,
        }
    }
}
pub const CLIENT_V4: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 1);
pub const ANCHOR_V4: Ipv4Addr = Ipv4Addr::new(198, 19, 255, 2);
pub const CLIENT_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 1);
pub const ANCHOR_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 2);
impl WindowsTunnelSettings {
    pub fn relay_pins(&self, relay: &crate::RelaySettings) -> Result<Vec<SocketAddr>, String> {
        use crate::TunnelTransportFamily as T;
        let udp = relay
            .udp_transport_priority
            .as_deref()
            .unwrap_or(&relay.transport_priority);
        if self.include_routes.is_empty() && udp.first() != Some(&T::GrpcDatagram) {
            return Err("full system tunnel requires grpc_datagram first for UDP; QUIC DATAGRAM cannot carry arbitrary fragmented UDP sizes".into());
        }
        if !relay.transport_priority.iter().any(|t| {
            matches!(
                t,
                T::LegacyTls | T::HttpsWs | T::GrpcStream | T::MasqueDerived
            )
        }) || !udp
            .iter()
            .any(|t| matches!(t, T::GrpcDatagram | T::MasqueDerived))
        {
            return Err("system tunnel requires executable TCP and UDP relay transports".into());
        }
        let mut values = vec![];
        if relay.endpoints.is_empty() {
            values.push(relay.server.as_str());
            if let Some(v) = relay.masque_server.as_deref() {
                values.push(v);
            }
        } else {
            for endpoint in &relay.endpoints {
                values.push(endpoint.server.as_str());
                if let Some(v) = endpoint
                    .masque_server
                    .as_deref()
                    .or(relay.masque_server.as_deref())
                {
                    values.push(v);
                }
            }
        }
        let mut pins = vec![];
        for value in values {
            let addr: SocketAddr = value.parse().map_err(|_| {
                "tunnel relay requires numeric dial addresses and a separate TLS server_name"
            })?;
            let synthetic = match addr.ip() {
                IpAddr::V4(v) => v.octets()[0] == 198 && (18..=19).contains(&v.octets()[1]),
                IpAddr::V6(v) => {
                    v.to_ipv4_mapped().is_some()
                        || v.segments()[0] == 0xfd00 && v.segments()[1] == 0xae61
                }
            };
            if addr.port() == 0
                || addr.ip().is_unspecified()
                || addr.ip().is_multicast()
                || synthetic
            {
                return Err("invalid pinned relay endpoint".into());
            }
            if !pins.contains(&addr) {
                pins.push(addr);
            }
        }
        if pins.is_empty() || pins.len() > 128 {
            return Err("relay endpoint count rejected".into());
        }
        Ok(pins)
    }
    pub fn routes(&self) -> Result<Vec<Prefix>, String> {
        let values = if self.include_routes.is_empty() {
            vec![
                "0.0.0.0/1".into(),
                "128.0.0.0/1".into(),
                "::/1".into(),
                "8000::/1".into(),
            ]
        } else {
            self.include_routes.clone()
        };
        if values.len() > 128 {
            return Err("too many split routes".into());
        }
        let mut result = Vec::new();
        for value in values {
            let prefix = Prefix::parse(&value)?;
            if result.contains(&prefix) {
                return Err("duplicate capture route".into());
            }
            result.push(prefix);
        }
        Ok(result)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.adapter_name.is_empty()
            || self.adapter_name.len() > 64
            || !self
                .adapter_name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b" -_".contains(&c))
        {
            return Err("invalid adapter name".into());
        }
        if !(1280..=1500).contains(&self.mtu)
            || !(1..=512).contains(&self.max_flows)
            || !(5..=3600).contains(&self.idle_timeout_secs)
        {
            return Err("tunnel resource limits rejected".into());
        }
        if self.dns_upstream.port() == 0
            || self.dns_upstream.ip().is_unspecified()
            || self.dns_upstream.ip().is_multicast()
            || self.dns_upstream.ip().is_loopback()
        {
            return Err("DNS upstream must be a remote unicast resolver".into());
        }
        if self.include_routes.is_empty() && (!self.kill_switch || !self.configure_dns) {
            return Err("full tunnel requires the kill switch and tunnel DNS".into());
        }
        self.routes()?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn full_profile_accepts_masque_tcp_with_large_datagram_transport() {
        let settings = WindowsTunnelSettings::default();
        let relay = crate::RelaySettings {
            server: "192.0.2.1:443".into(),
            transport_priority: vec![crate::TunnelTransportFamily::MasqueDerived],
            udp_transport_priority: Some(vec![crate::TunnelTransportFamily::GrpcDatagram]),
            ..Default::default()
        };
        assert_eq!(
            settings.relay_pins(&relay).unwrap(),
            vec!["192.0.2.1:443".parse::<SocketAddr>().unwrap()]
        );
    }
    #[test]
    fn full_routes_cover_both_families() {
        let cfg = WindowsTunnelSettings::default();
        cfg.validate().unwrap();
        for ip in ["1.1.1.1", "192.168.1.1", "2606:4700::1111", "fd42::1"] {
            assert_eq!(
                cfg.routes()
                    .unwrap()
                    .iter()
                    .filter(|p| p.contains(ip.parse().unwrap()))
                    .count(),
                1
            );
        }
    }
    #[test]
    fn malformed_routes_and_unsafe_scope_are_rejected() {
        for value in ["10.1.2.3/8", "::1/64", "1.1.1.1/33", "::/129", "1.1.1.1"] {
            assert!(Prefix::parse(value).is_err());
        }
        let cfg = WindowsTunnelSettings {
            kill_switch: false,
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }
}
