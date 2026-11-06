//! Input plumbing for witness classification.

use std::{collections::HashSet, fs, io::Read, path::PathBuf};

use thiserror::Error;

use crate::{
    pcap::parse_pcap,
    tcp::{extract_tcp_ipv4_payload_checked, validate_pcap_link_type, TcpPayloadError},
};

#[derive(Debug, Error)]
pub enum CaptureError {
    #[error("exactly one input source must be selected")]
    InvalidSourceSelection,
    #[error("interface capture is not implemented in this slice: {0}")]
    InterfaceUnsupported(String),
    #[error("failed to decode hex input: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("failed to read input: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse pcap input: {0}")]
    Pcap(#[from] crate::pcap::PcapError),
    #[error("failed to decode PCAP packet: {0}")]
    PcapDecode(#[from] TcpPayloadError),
    #[error("PCAP input contains no packets")]
    EmptyPcap,
    #[error("PCAP input contains no supported nonempty TCP payloads")]
    NoTcpPayload,
    #[error("TCP stream reassembly is unsupported (second payload at packet {packet})")]
    TcpStreamUnsupported { packet: usize },
    #[error("PCAP packet {packet} requires unsupported TLS framing: {reason}")]
    TlsFramingUnsupported { packet: usize, reason: &'static str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSource {
    Hex(String),
    File(PathBuf),
    PcapFile(PathBuf),
    Stdin,
    Interface(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRecord {
    pub label_suffix: Option<String>,
    pub bytes: Vec<u8>,
}

impl InputSource {
    pub fn read_records(self) -> Result<Vec<CapturedRecord>, CaptureError> {
        match self {
            Self::Hex(hex) => Ok(vec![CapturedRecord {
                label_suffix: None,
                bytes: hex::decode(hex.trim())?,
            }]),
            Self::File(path) => Ok(vec![CapturedRecord {
                label_suffix: None,
                bytes: fs::read(path)?,
            }]),
            Self::PcapFile(path) => {
                let data = fs::read(path)?;
                let pcap = parse_pcap(&data)?;
                validate_pcap_link_type(pcap.link_type)?;
                if pcap.packets.is_empty() {
                    return Err(CaptureError::EmptyPcap);
                }
                let mut payload_flows = HashSet::new();
                let mut records = Vec::new();
                for packet in pcap.packets {
                    if let Some(tcp) =
                        extract_tcp_ipv4_payload_checked(pcap.link_type, &packet.data)?
                    {
                        if tcp.payload.is_empty() {
                            continue;
                        }
                        let flow = (tcp.src_addr, tcp.src_port, tcp.dst_addr, tcp.dst_port);
                        if !payload_flows.insert(flow) {
                            return Err(CaptureError::TcpStreamUnsupported {
                                packet: packet.index,
                            });
                        }
                        records.push((
                            packet.index,
                            CapturedRecord {
                                label_suffix: Some(format!(
                                    "packet={} {}:{}->{}:{}",
                                    packet.index,
                                    tcp.src_addr,
                                    tcp.src_port,
                                    tcp.dst_addr,
                                    tcp.dst_port
                                )),
                                bytes: tcp.payload,
                            },
                        ));
                    }
                }
                if records.is_empty() {
                    return Err(CaptureError::NoTcpPayload);
                }
                // Validate the entire input before exposing any classification.
                // No segment is interpreted as an independent TLS-negative
                // observation when its framing requires reassembly.
                for (packet, record) in &records {
                    validate_single_tls_record(&record.bytes).map_err(|reason| {
                        CaptureError::TlsFramingUnsupported {
                            packet: *packet,
                            reason,
                        }
                    })?;
                }
                Ok(records.into_iter().map(|(_, record)| record).collect())
            }
            Self::Stdin => {
                let mut data = Vec::new();
                std::io::stdin().read_to_end(&mut data)?;
                Ok(vec![CapturedRecord {
                    label_suffix: None,
                    bytes: data,
                }])
            }
            Self::Interface(name) => Err(CaptureError::InterfaceUnsupported(name)),
        }
    }
}

pub fn select_source(
    input_hex: Option<String>,
    input_file: Option<PathBuf>,
    input_pcap: Option<PathBuf>,
    stdin: bool,
    interface: Option<String>,
) -> Result<InputSource, CaptureError> {
    let selected = usize::from(input_hex.is_some())
        + usize::from(input_file.is_some())
        + usize::from(input_pcap.is_some())
        + usize::from(stdin)
        + usize::from(interface.is_some());
    if selected != 1 {
        return Err(CaptureError::InvalidSourceSelection);
    }

    if let Some(hex) = input_hex {
        return Ok(InputSource::Hex(hex));
    }
    if let Some(path) = input_file {
        return Ok(InputSource::File(path));
    }
    if let Some(path) = input_pcap {
        return Ok(InputSource::PcapFile(path));
    }
    if stdin {
        return Ok(InputSource::Stdin);
    }
    Ok(InputSource::Interface(
        interface.expect("selected interface"),
    ))
}

/// The PCAP classifier deliberately supports only one complete TLS record per
/// TCP payload. Raw file/hex/stdin inputs retain the general classifier API.
fn validate_single_tls_record(payload: &[u8]) -> Result<(), &'static str> {
    if payload.len() < 5 || !(20..=24).contains(&payload[0]) || payload[1] != 3 {
        return Err("payload is not a complete supported TLS record");
    }
    let record_len = usize::from(u16::from_be_bytes([payload[3], payload[4]]));
    if record_len != payload.len() - 5 {
        return Err("split, truncated, or coalesced TLS records");
    }
    if payload[0] == 22 {
        let handshake = &payload[5..];
        if handshake.len() < 4 {
            return Err("short TLS handshake header");
        }
        let handshake_len = (usize::from(handshake[1]) << 16)
            | (usize::from(handshake[2]) << 8)
            | usize::from(handshake[3]);
        if handshake_len != handshake.len() - 4 {
            return Err("split or coalesced TLS handshake messages");
        }
    }
    Ok(())
}
