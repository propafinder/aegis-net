use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::fingerprint::{ServerType, WindowProfile};

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetKind {
    Domain,
    Ipv4Literal,
    Ipv6Literal,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum TargetClass {
    WebTls,
    WebPlain,
    Dns,
    Ssh,
    Mail,
    LoopbackService,
    PrivateService,
    GenericTcp,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkHint {
    Loopback,
    Private,
    Public,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModeHint {
    Direct,
    Relay,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacketStageHint {
    SynAckSeen,
    FirstDataSeen,
    ResetSeen,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum PathHopHint {
    Near,
    Mid,
    Far,
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResetProfileHint {
    RemotePath,
    MiddleboxPath,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
pub struct StrategyKey {
    pub ip_version: u8,
    pub dst_subnet: String,
    pub target_host_hash: u64,
    pub target_port: u16,
    pub port_bucket: u16,
    pub sni_hash: Option<u64>,
    pub server_signature_hash: Option<u64>,
    pub target_kind: TargetKind,
    pub target_class: TargetClass,
    pub network_hint: NetworkHint,
    pub server_hint: Option<ServerType>,
    pub packet_stage_hint: Option<PacketStageHint>,
    pub fingerprint_window_hint: Option<WindowProfile>,
    pub reference_hop_hint: Option<PathHopHint>,
    pub reset_profile_hint: Option<ResetProfileHint>,
    pub mode_hint: ModeHint,
    pub is_tls: bool,
}

impl StrategyKey {
    pub fn for_dst(ip_version: u8) -> Self {
        let dst = match ip_version {
            6 => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            _ => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        };
        Self::for_target(dst, "unknown", 0, None, false)
    }

    pub fn for_target(
        dst: SocketAddr,
        target_host: &str,
        target_port: u16,
        sni: Option<&str>,
        is_tls: bool,
    ) -> Self {
        let network_hint = classify_network_hint(dst.ip());
        let target_kind = classify_target_kind(target_host);
        Self {
            ip_version: if dst.is_ipv4() { 4 } else { 6 },
            dst_subnet: bucket_subnet(dst.ip()),
            target_host_hash: stable_hash64(target_host),
            target_port,
            port_bucket: bucket_port(target_port),
            sni_hash: sni.map(stable_hash64),
            server_signature_hash: None,
            target_kind,
            target_class: classify_target_class(network_hint, target_port, is_tls),
            network_hint,
            server_hint: None,
            packet_stage_hint: None,
            fingerprint_window_hint: None,
            reference_hop_hint: None,
            reset_profile_hint: None,
            mode_hint: ModeHint::Direct,
            is_tls,
        }
    }

    pub fn hash_key(&self) -> String {
        let bytes = serde_json::to_vec(self).expect("serialize strategy key");
        let mut h = Sha256::new();
        h.update(&bytes);
        hex::encode(h.finalize())
    }
}

fn stable_hash64(value: &str) -> u64 {
    let digest = Sha256::digest(value.as_bytes());
    u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ])
}

fn classify_target_kind(target_host: &str) -> TargetKind {
    if target_host.parse::<Ipv4Addr>().is_ok() {
        TargetKind::Ipv4Literal
    } else if target_host.parse::<Ipv6Addr>().is_ok() {
        TargetKind::Ipv6Literal
    } else {
        TargetKind::Domain
    }
}

fn classify_network_hint(ip: IpAddr) -> NetworkHint {
    match ip {
        IpAddr::V4(v4) => {
            if v4.is_loopback() {
                NetworkHint::Loopback
            } else if v4.is_private() || v4.is_link_local() {
                NetworkHint::Private
            } else {
                NetworkHint::Public
            }
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() {
                NetworkHint::Loopback
            } else if v6.is_unique_local() || v6.is_unicast_link_local() {
                NetworkHint::Private
            } else {
                NetworkHint::Public
            }
        }
    }
}

fn classify_target_class(network_hint: NetworkHint, target_port: u16, is_tls: bool) -> TargetClass {
    match network_hint {
        NetworkHint::Loopback => TargetClass::LoopbackService,
        NetworkHint::Private => TargetClass::PrivateService,
        NetworkHint::Public => match target_port {
            53 | 853 => TargetClass::Dns,
            22 => TargetClass::Ssh,
            25 | 465 | 587 | 993 | 995 => TargetClass::Mail,
            80 | 8000 | 8008 | 8080 | 8081 => TargetClass::WebPlain,
            443 | 8443 => TargetClass::WebTls,
            _ if is_tls => TargetClass::WebTls,
            _ => TargetClass::GenericTcp,
        },
    }
}

fn bucket_port(port: u16) -> u16 {
    match port {
        0 => 0,
        53 | 80 | 123 | 443 | 853 | 8443 => port,
        1..=1023 => 1023,
        1024..=49151 => 49151,
        _ => 65535,
    }
}

fn bucket_subnet(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
    }
}
