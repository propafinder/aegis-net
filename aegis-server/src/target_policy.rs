//! Authenticated relay egress policy and resolve-once target validation.

use crate::config::{TargetPolicyConfig, TargetPolicyProfile};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::TcpStream;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetDenyReason {
    PortZero,
    PortNotAllowed,
    NonPublicAddress,
}

impl std::fmt::Display for TargetDenyReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PortZero => f.write_str("target port zero is not allowed"),
            Self::PortNotAllowed => f.write_str("target port is outside the configured allowlist"),
            Self::NonPublicAddress => {
                f.write_str("non-public target requires target_policy.profile=full_vpn_egress")
            }
        }
    }
}

pub fn validate_target(
    address: SocketAddr,
    policy: &TargetPolicyConfig,
) -> Result<(), TargetDenyReason> {
    if address.port() == 0 {
        return Err(TargetDenyReason::PortZero);
    }
    if !policy.allowed_ports.is_empty() && !policy.allowed_ports.contains(&address.port()) {
        return Err(TargetDenyReason::PortNotAllowed);
    }
    if policy.profile == TargetPolicyProfile::PublicInternet && !is_public_ip(address.ip()) {
        return Err(TargetDenyReason::NonPublicAddress);
    }
    Ok(())
}

/// Resolve once, validate every result, and return only exact socket addresses.
/// Callers must connect to these addresses directly; reconnecting by hostname
/// would reopen a DNS-rebinding TOCTOU window.
pub async fn resolve_allowed_targets(
    host: &str,
    port: u16,
    policy: &TargetPolicyConfig,
) -> io::Result<Vec<SocketAddr>> {
    resolve_allowed_targets_with_logging(
        host,
        port,
        policy,
        crate::operational_log::OperationalLogPolicy::default(),
    )
    .await
}

pub(crate) async fn resolve_allowed_targets_with_logging(
    host: &str,
    port: u16,
    policy: &TargetPolicyConfig,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> io::Result<Vec<SocketAddr>> {
    if port == 0 {
        return Err(policy_denied(host, port, TargetDenyReason::PortZero));
    }
    if !policy.allowed_ports.is_empty() && !policy.allowed_ports.contains(&port) {
        return Err(policy_denied(host, port, TargetDenyReason::PortNotAllowed));
    }

    let candidates: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        tokio::net::lookup_host((host, port)).await?.collect()
    };
    if candidates.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("target {host}:{port} resolved to no addresses"),
        ));
    }

    let mut allowed = Vec::new();
    let mut denied = Vec::new();
    for address in candidates {
        match validate_target(address, policy) {
            Ok(()) => {
                if !allowed.contains(&address) {
                    allowed.push(address);
                }
            }
            Err(reason) => denied.push((address, reason)),
        }
    }
    if allowed.is_empty() {
        let reason = denied
            .first()
            .map(|(_, reason)| *reason)
            .unwrap_or(TargetDenyReason::NonPublicAddress);
        crate::operational_log::warn_counted(
            operational_log,
            crate::operational_log::FailureStage::TargetPolicy,
            crate::operational_log::FailureReason::PolicyDenied,
            None,
            denied.len(),
            &format_args!(
                "target={host}:{port} profile={:?} reason={reason}",
                policy.profile
            ),
        );
        return Err(policy_denied(host, port, reason));
    }
    if !denied.is_empty() {
        crate::operational_log::warn_counted(
            operational_log,
            crate::operational_log::FailureStage::TargetPolicy,
            crate::operational_log::FailureReason::PartialDnsDenial,
            None,
            denied.len(),
            &format_args!(
                "target={host}:{port} profile={:?} allowed_addresses={}",
                policy.profile,
                allowed.len()
            ),
        );
    }
    Ok(allowed)
}

pub async fn connect_tcp_target(
    host: &str,
    port: u16,
    policy: &TargetPolicyConfig,
) -> io::Result<TcpStream> {
    connect_tcp_target_with_logging(
        host,
        port,
        policy,
        crate::operational_log::OperationalLogPolicy::default(),
    )
    .await
}

pub(crate) async fn connect_tcp_target_with_logging(
    host: &str,
    port: u16,
    policy: &TargetPolicyConfig,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> io::Result<TcpStream> {
    let addresses =
        resolve_allowed_targets_with_logging(host, port, policy, operational_log).await?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("target {host}:{port} has no connectable allowed addresses"),
        )
    }))
}

fn policy_denied(host: &str, port: u16, reason: TargetDenyReason) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        format!("target policy denied {host}:{port}: {reason}"),
    )
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_public_ipv4(ip),
        IpAddr::V6(ip) => is_public_ipv6(ip),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let value = u32::from(ip);
    !cidr4(value, 0x0000_0000, 8) // current network / unspecified
        && !cidr4(value, 0x0a00_0000, 8) // RFC1918
        && !cidr4(value, 0x6440_0000, 10) // shared address space
        && !cidr4(value, 0x7f00_0000, 8) // loopback
        && !cidr4(value, 0xa9fe_0000, 16) // link-local + metadata
        && !cidr4(value, 0xac10_0000, 12) // RFC1918
        && !cidr4(value, 0xc000_0000, 24) // IETF protocol assignments
        && !cidr4(value, 0xc000_0200, 24) // documentation
        && !cidr4(value, 0xc058_6300, 24) // deprecated 6to4 relay anycast
        && !cidr4(value, 0xc0a8_0000, 16) // RFC1918
        && !cidr4(value, 0xc612_0000, 15) // benchmark tests
        && !cidr4(value, 0xc633_6400, 24) // documentation
        && !cidr4(value, 0xcb00_7100, 24) // documentation
        && !cidr4(value, 0xe000_0000, 4) // multicast
        && !cidr4(value, 0xf000_0000, 4) // reserved + broadcast
}

fn cidr4(value: u32, network: u32, prefix: u8) -> bool {
    let mask = u32::MAX.checked_shl((32 - prefix) as u32).unwrap_or(0);
    value & mask == network & mask
}

fn is_public_ipv6(ip: Ipv6Addr) -> bool {
    if let Some(mapped) = ip.to_ipv4_mapped() {
        return is_public_ipv4(mapped);
    }
    let value = u128::from(ip);
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_multicast()
        && !cidr6(value, 0x0064_ff9b_0000_0000_0000_0000_0000_0000, 96) // NAT64 WKP
        && !cidr6(value, 0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48) // local-use NAT64
        && !cidr6(value, 0x0100_0000_0000_0000_0000_0000_0000_0000, 64) // discard-only
        && !cidr6(value, 0x2001_0000_0000_0000_0000_0000_0000_0000, 23) // IETF assignments
        && !cidr6(value, 0x2001_0db8_0000_0000_0000_0000_0000_0000, 32) // documentation
        && !cidr6(value, 0x2002_0000_0000_0000_0000_0000_0000_0000, 16) // 6to4
        && !cidr6(value, 0x3fff_0000_0000_0000_0000_0000_0000_0000, 20) // documentation
        && !cidr6(value, 0x5f00_0000_0000_0000_0000_0000_0000_0000, 16) // segment-routing SIDs
        && !cidr6(value, 0xfc00_0000_0000_0000_0000_0000_0000_0000, 7) // ULA
        && !cidr6(value, 0xfe80_0000_0000_0000_0000_0000_0000_0000, 10) // link-local
        && !cidr6(value, 0xfec0_0000_0000_0000_0000_0000_0000_0000, 10) // site-local
}

fn cidr6(value: u128, network: u128, prefix: u8) -> bool {
    let mask = u128::MAX.checked_shl((128 - prefix) as u32).unwrap_or(0);
    value & mask == network & mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn public_policy() -> TargetPolicyConfig {
        TargetPolicyConfig::default()
    }

    #[test]
    fn public_profile_denies_ssrf_address_matrix() {
        let denied = [
            "127.0.0.1:80",
            "10.0.0.1:443",
            "172.16.0.1:53",
            "192.168.1.1:22",
            "169.254.169.254:80",
            "100.64.0.1:80",
            "198.18.0.1:443",
            "[::1]:80",
            "[fc00::1]:443",
            "[fe80::1]:53",
            "[::ffff:127.0.0.1]:80",
            "[64:ff9b::c0a8:1]:443",
            "[64:ff9b:1::1]:443",
            "[100::1]:443",
            "[2001::1]:443",
            "[2001:db8::1]:443",
            "[2002:c0a8:1::1]:443",
            "[3fff::1]:443",
            "[5f00::1]:443",
        ];
        for value in denied {
            let address: SocketAddr = value.parse().unwrap();
            assert_eq!(
                validate_target(address, &public_policy()),
                Err(TargetDenyReason::NonPublicAddress),
                "unexpected allow for {value}"
            );
        }
    }

    #[test]
    fn public_and_full_vpn_profiles_are_explicitly_distinct() {
        let public: SocketAddr = "1.1.1.1:443".parse().unwrap();
        let private: SocketAddr = "10.0.0.1:443".parse().unwrap();
        assert_eq!(validate_target(public, &public_policy()), Ok(()));
        assert!(validate_target(private, &public_policy()).is_err());

        let full_vpn = TargetPolicyConfig {
            profile: TargetPolicyProfile::FullVpnEgress,
            allowed_ports: Vec::new(),
        };
        assert_eq!(validate_target(private, &full_vpn), Ok(()));
    }

    #[test]
    fn configured_port_allowlist_is_enforced() {
        let policy = TargetPolicyConfig {
            profile: TargetPolicyProfile::PublicInternet,
            allowed_ports: vec![443],
        };
        assert_eq!(
            validate_target("1.1.1.1:80".parse().unwrap(), &policy),
            Err(TargetDenyReason::PortNotAllowed)
        );
        assert_eq!(
            validate_target("1.1.1.1:443".parse().unwrap(), &policy),
            Ok(())
        );
    }
}
