//! Minimal classic PCAP reader for offline witness ingestion.

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapFile {
    pub link_type: u32,
    pub packets: Vec<PcapPacket>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapPacket {
    pub index: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PcapError {
    #[error("pcap input is shorter than global header")]
    ShortGlobalHeader,
    #[error("unsupported pcap magic")]
    UnsupportedMagic,
    #[error("pcap packet header is truncated at offset {0}")]
    TruncatedPacketHeader(usize),
    #[error("pcap packet data is truncated at offset {offset}, caplen {caplen}")]
    TruncatedPacketData { offset: usize, caplen: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        match self {
            Self::Little => u16::from_le_bytes([bytes[0], bytes[1]]),
            Self::Big => u16::from_be_bytes([bytes[0], bytes[1]]),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            Self::Big => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        }
    }
}

pub fn parse_pcap(data: &[u8]) -> Result<PcapFile, PcapError> {
    if data.len() < 24 {
        return Err(PcapError::ShortGlobalHeader);
    }

    let endian = match data.get(0..4) {
        Some([0xd4, 0xc3, 0xb2, 0xa1]) | Some([0x4d, 0x3c, 0xb2, 0xa1]) => Endian::Little,
        Some([0xa1, 0xb2, 0xc3, 0xd4]) | Some([0xa1, 0xb2, 0x3c, 0x4d]) => Endian::Big,
        _ => return Err(PcapError::UnsupportedMagic),
    };

    let _version_major = endian.u16(&data[4..6]);
    let _version_minor = endian.u16(&data[6..8]);
    let link_type = endian.u32(&data[20..24]);
    let mut packets = Vec::new();
    let mut offset = 24usize;
    let mut index = 0usize;

    while offset < data.len() {
        if offset + 16 > data.len() {
            return Err(PcapError::TruncatedPacketHeader(offset));
        }
        let caplen = endian.u32(&data[offset + 8..offset + 12]) as usize;
        offset += 16;
        if offset + caplen > data.len() {
            return Err(PcapError::TruncatedPacketData { offset, caplen });
        }
        packets.push(PcapPacket {
            index,
            data: data[offset..offset + caplen].to_vec(),
        });
        index += 1;
        offset += caplen;
    }

    Ok(PcapFile { link_type, packets })
}
