//! Conservative IPv4/TCP payload extraction for offline PCAP witnesses.

use std::{fmt, net::Ipv4Addr};

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpIpv4Payload {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TcpPayloadError {
    #[error("unsupported PCAP link type {0}")]
    UnsupportedLinkType(u32),
    #[error("IPv6 PCAP payloads are unsupported")]
    UnsupportedIpv6,
    #[error("stacked VLAN PCAP frames are unsupported")]
    UnsupportedStackedVlan,
    #[error("IPv4 fragmentation is unsupported")]
    UnsupportedIpv4Fragmentation,
    #[error("malformed PCAP frame: {0}")]
    MalformedFrame(&'static str),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkType {
    Ethernet,
    RawIp,
}

impl LinkType {
    fn from_pcap(link_type: u32) -> Result<Self, TcpPayloadError> {
        match link_type {
            1 => Ok(Self::Ethernet),
            101 | 228 => Ok(Self::RawIp),
            _ => Err(TcpPayloadError::UnsupportedLinkType(link_type)),
        }
    }
}

impl fmt::Display for TcpIpv4Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}->{}:{}",
            self.src_addr, self.src_port, self.dst_addr, self.dst_port
        )
    }
}

/// Validate the link type even when a capture contains no packets.
pub fn validate_pcap_link_type(link_type: u32) -> Result<(), TcpPayloadError> {
    LinkType::from_pcap(link_type).map(|_| ())
}

/// Compatibility helper. Capture ingestion uses the checked helper below so
/// malformed or unsupported packets cannot silently disappear from a report.
pub fn extract_tcp_ipv4_payload(link_type: u32, frame: &[u8]) -> Option<TcpIpv4Payload> {
    extract_tcp_ipv4_payload_checked(link_type, frame)
        .ok()
        .flatten()
}

pub fn extract_tcp_ipv4_payload_checked(
    link_type: u32,
    frame: &[u8],
) -> Result<Option<TcpIpv4Payload>, TcpPayloadError> {
    match LinkType::from_pcap(link_type)? {
        LinkType::Ethernet => match ethernet_ipv4_payload(frame)? {
            Some(ipv4) => parse_ipv4_tcp_payload(ipv4),
            None => Ok(None),
        },
        LinkType::RawIp => parse_ipv4_tcp_payload(frame),
    }
}

fn ethernet_ipv4_payload(frame: &[u8]) -> Result<Option<&[u8]>, TcpPayloadError> {
    if frame.len() < 14 {
        return Err(TcpPayloadError::MalformedFrame("short Ethernet header"));
    }
    let mut ether_type = u16::from_be_bytes([frame[12], frame[13]]);
    let mut offset = 14usize;
    if ether_type == 0x8100 || ether_type == 0x88a8 {
        if frame.len() < 18 {
            return Err(TcpPayloadError::MalformedFrame("short VLAN header"));
        }
        ether_type = u16::from_be_bytes([frame[16], frame[17]]);
        offset = 18;
        if ether_type == 0x8100 || ether_type == 0x88a8 {
            return Err(TcpPayloadError::UnsupportedStackedVlan);
        }
    }
    match ether_type {
        0x86dd => Err(TcpPayloadError::UnsupportedIpv6),
        0x0800 => Ok(Some(&frame[offset..])),
        _ => Ok(None),
    }
}

fn parse_ipv4_tcp_payload(packet: &[u8]) -> Result<Option<TcpIpv4Payload>, TcpPayloadError> {
    if packet.first().is_some_and(|version| version >> 4 == 6) {
        return Err(TcpPayloadError::UnsupportedIpv6);
    }
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return Err(TcpPayloadError::MalformedFrame("short or non-IPv4 header"));
    }
    let ihl = usize::from(packet[0] & 0x0f) * 4;
    if ihl < 20 || packet.len() < ihl {
        return Err(TcpPayloadError::MalformedFrame(
            "invalid IPv4 header length",
        ));
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < ihl || total_len > packet.len() {
        return Err(TcpPayloadError::MalformedFrame("invalid IPv4 total length"));
    }
    if packet[9] != 6 {
        return Ok(None);
    }
    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_fragment & 0x3fff != 0 {
        return Err(TcpPayloadError::UnsupportedIpv4Fragmentation);
    }

    let src_addr = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let dst_addr = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let tcp = &packet[ihl..total_len];
    if tcp.len() < 20 {
        return Err(TcpPayloadError::MalformedFrame("short TCP header"));
    }
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let dst_port = u16::from_be_bytes([tcp[2], tcp[3]]);
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < 20 || tcp.len() < data_offset {
        return Err(TcpPayloadError::MalformedFrame("invalid TCP data offset"));
    }
    Ok(Some(TcpIpv4Payload {
        src_addr,
        dst_addr,
        src_port,
        dst_port,
        payload: tcp[data_offset..].to_vec(),
    }))
}
