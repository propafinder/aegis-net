use std::{fs, io::Write, path::Path};

use serde_json::Value;

pub fn sll2_to_rawip(data: &[u8]) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
    if data.len() < 24 {
        return Ok(None);
    }
    let endian = match &data[0..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] | [0x4d, 0x3c, 0xb2, 0xa1] => Endian::Little,
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xa1, 0xb2, 0x3c, 0x4d] => Endian::Big,
        _ => return Ok(None),
    };
    if endian.u32(&data[20..24]) != 276 {
        return Ok(None);
    }

    let mut out = data[0..24].to_vec();
    endian.write_u32(&mut out[20..24], 101);
    let mut offset = 24usize;
    let mut converted = 0usize;
    while offset < data.len() {
        if offset + 16 > data.len() {
            break;
        }
        let ts_sec = endian.u32(&data[offset..offset + 4]);
        let ts_usec = endian.u32(&data[offset + 4..offset + 8]);
        let caplen = endian.u32(&data[offset + 8..offset + 12]) as usize;
        offset += 16;
        if offset + caplen > data.len() {
            break;
        }
        let frame = &data[offset..offset + caplen];
        offset += caplen;
        if frame.len() < 20 {
            continue;
        }
        let protocol = u16::from_be_bytes([frame[0], frame[1]]);
        if protocol != 0x0800 && protocol != 0x86dd {
            continue;
        }
        let raw = &frame[20..];
        if raw.is_empty() {
            continue;
        }
        let mut header = [0u8; 16];
        endian.write_u32(&mut header[0..4], ts_sec);
        endian.write_u32(&mut header[4..8], ts_usec);
        endian.write_u32(&mut header[8..12], raw.len() as u32);
        endian.write_u32(&mut header[12..16], raw.len() as u32);
        out.extend_from_slice(&header);
        out.extend_from_slice(raw);
        converted += 1;
    }
    Ok((converted > 0).then_some(out))
}

pub fn suricata_alert_count(path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut count = 0usize;
    for line in fs::read_to_string(path)?.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value["event_type"].as_str() == Some("alert") {
            count += 1;
        }
    }
    std::io::stdout().flush().ok();
    Ok(count)
}

pub fn ndpi_risk_count(path: &Path) -> Result<usize, Box<dyn std::error::Error>> {
    let mut in_risk_stats = false;
    let mut count = 0usize;
    for line in fs::read_to_string(path)?.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("Risk stats") {
            in_risk_stats = true;
            continue;
        }
        if !in_risk_stats {
            continue;
        }
        if trimmed.is_empty() {
            if count > 0 {
                break;
            }
            continue;
        }
        if trimmed.starts_with("NOTE:") || trimmed.starts_with("as one flow") {
            break;
        }
        if trimmed
            .chars()
            .next()
            .is_some_and(|first| first.is_alphabetic())
            && trimmed.contains('[')
            && trimmed.contains('%')
        {
            count += 1;
        }
    }
    std::io::stdout().flush().ok();
    Ok(count)
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u32(self, bytes: &[u8]) -> u32 {
        match self {
            Self::Little => u32::from_le_bytes(bytes.try_into().expect("u32 bytes")),
            Self::Big => u32::from_be_bytes(bytes.try_into().expect("u32 bytes")),
        }
    }

    fn write_u32(self, bytes: &mut [u8], value: u32) {
        let encoded = match self {
            Self::Little => value.to_le_bytes(),
            Self::Big => value.to_be_bytes(),
        };
        bytes.copy_from_slice(&encoded);
    }
}
