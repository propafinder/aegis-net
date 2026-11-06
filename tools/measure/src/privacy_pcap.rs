//! Exact private classic-PCAP subset exporter. No live capture or payload export.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fmt::{self, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::Path,
};

const MAX_INPUT: usize = 64 * 1024 * 1024;
const MAX_OUTPUT: usize = 4 * 1024 * 1024;
const MAX_RECORDS: usize = 262_144;
const MAX_FRAME: usize = 65_535;

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn private_path(path: &Path) -> Result<(), &'static str> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err("PCAP export needs bounded absolute private paths");
    }
    aegis_core::secret_file::trusted_parent(path)
        .map(|_| ())
        .map_err(|_| "PCAP export ancestry is not private")
}

pub fn run(input: &Path, output: &Path) -> Result<Value, &'static str> {
    private_path(input)?;
    private_path(output)?;
    let bytes = aegis_core::secret_file::read(input, MAX_INPUT as u64)
        .map_err(|_| "PCAP input must be a bounded descriptor-checked private file")?;
    let converted = convert(&bytes, MAX_OUTPUT, MAX_RECORDS)?;
    aegis_core::secret_file::write_private_new(output, &converted.tsv)
        .map_err(|_| "PCAP export output must be a new private file")?;
    Ok(converted.summary)
}

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}
impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        let bytes = [bytes[0], bytes[1]];
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }
    fn u32(self, bytes: &[u8]) -> u32 {
        let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}
struct Converted {
    tsv: Vec<u8>,
    summary: Value,
}
struct Fields {
    source: IpAddr,
    destination: IpAddr,
    protocol: &'static str,
    source_port: u16,
    destination_port: u16,
}
// Formatting cannot allocate a growing string containing private endpoints.
struct Row {
    bytes: [u8; 256],
    used: usize,
}
impl Row {
    fn new() -> Self {
        Self {
            bytes: [0; 256],
            used: 0,
        }
    }
}
impl fmt::Write for Row {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let next = self.used.checked_add(text.len()).ok_or(fmt::Error)?;
        let destination = self.bytes.get_mut(self.used..next).ok_or(fmt::Error)?;
        destination.copy_from_slice(text.as_bytes());
        self.used = next;
        Ok(())
    }
}
fn append(output: &mut [u8], used: &mut usize, bytes: &[u8]) -> Result<(), &'static str> {
    let next = used
        .checked_add(bytes.len())
        .ok_or("PCAP export output budget exceeded")?;
    output
        .get_mut(*used..next)
        .ok_or("PCAP export output budget exceeded")?
        .copy_from_slice(bytes);
    *used = next;
    Ok(())
}

fn convert(
    data: &[u8],
    output_budget: usize,
    record_budget: usize,
) -> Result<Converted, &'static str> {
    if !(24..=MAX_INPUT).contains(&data.len())
        || output_budget > MAX_OUTPUT
        || record_budget > MAX_RECORDS
    {
        return Err("PCAP input or conversion budget rejected");
    }
    let (endian, nanos) = match &data[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (Endian::Little, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (Endian::Big, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (Endian::Little, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (Endian::Big, true),
        _ => return Err("only classic PCAP magic is supported"),
    };
    if endian.u16(&data[4..6]) != 2 || endian.u16(&data[6..8]) != 4 {
        return Err("only classic PCAP version 2.4 is supported");
    }
    // Reserved1/2 are ignored, as required by the PCAP format; they do not
    // establish timezone correction or clock accuracy.
    let snaplen = endian.u32(&data[16..20]) as usize;
    let link = endian.u32(&data[20..24]);
    if snaplen == 0 || ![1, 101].contains(&link) {
        // Reject additional FCS/link flags as well as unsupported link types.
        return Err("PCAP snapshot or plain Ethernet/raw-IP link rejected");
    }
    let mut output = vec![0; output_budget];
    let mut used = 0;
    append(
        &mut output,
        &mut used,
        crate::privacy_study::PACKET_ROWS_V1_HEADER.as_bytes(),
    )?;
    append(&mut output, &mut used, b"\n")?;
    let mut offset = 24usize;
    let mut count = 0usize;
    let mut first = None;
    let mut last = None;
    let mut frame_bytes = 0u64;
    while offset < data.len() {
        count = count.checked_add(1).ok_or("PCAP record budget exceeded")?;
        if count > record_budget {
            return Err("PCAP record budget exceeded");
        }
        let header_end = offset
            .checked_add(16)
            .ok_or("PCAP record header overflow")?;
        let header = data
            .get(offset..header_end)
            .ok_or("PCAP record header is partial")?;
        let seconds = u64::from(endian.u32(&header[..4]));
        let fraction = u64::from(endian.u32(&header[4..8]));
        if fraction >= if nanos { 1_000_000_000 } else { 1_000_000 }
            || nanos && fraction % 1000 != 0
        {
            return Err("PCAP timestamp is invalid or not exact integer microseconds");
        }
        let timestamp = seconds
            .checked_mul(1_000_000)
            .and_then(|seconds| seconds.checked_add(if nanos { fraction / 1000 } else { fraction }))
            .ok_or("PCAP timestamp overflow")?;
        if last.is_some_and(|previous| timestamp < previous) {
            return Err("PCAP timestamps must preserve nondecreasing record order");
        }
        let captured = endian.u32(&header[8..12]) as usize;
        let original = endian.u32(&header[12..16]) as usize;
        if captured == 0 || captured != original || captured > snaplen || captured > MAX_FRAME {
            return Err("PCAP record is truncated or outside frame/snapshot budget");
        }
        let frame_end = header_end
            .checked_add(captured)
            .ok_or("PCAP frame overflow")?;
        let frame = data
            .get(header_end..frame_end)
            .ok_or("PCAP frame data is partial")?;
        let fields = packet_fields(link, frame)?;
        let mut row = Row::new();
        writeln!(
            &mut row,
            "{timestamp}\t{original}\t{captured}\t{}\t{}\t{}\t{}\t{}",
            fields.source,
            fields.destination,
            fields.protocol,
            fields.source_port,
            fields.destination_port
        )
        .map_err(|_| "PCAP row formatting budget exceeded")?;
        append(&mut output, &mut used, &row.bytes[..row.used])?;
        frame_bytes = frame_bytes
            .checked_add(original as u64)
            .ok_or("PCAP frame byte accounting overflow")?;
        first.get_or_insert(timestamp);
        last = Some(timestamp);
        offset = frame_end;
    }
    if count == 0 {
        return Err("PCAP trial has no supported packet records");
    }
    output.truncate(used);
    let summary = json!({
        "schema": "aegis_private_pcap_export_v1",
        "input_pcap_sha256": digest(data),
        "output_tsv_sha256": digest(&output),
        "link_type": link,
        "timestamp_input_units": if nanos { "nanoseconds_exactly_divisible_by_1000" } else { "microseconds" },
        "timestamp_output_units": "integer_unix_microseconds",
        "records_seen": count,
        "rows_emitted": count,
        "records_skipped": 0,
        "declared_frame_bytes": frame_bytes,
        "first_observed_packet_unix_us": first,
        "last_observed_packet_unix_us": last,
        "input_byte_count": data.len(),
        "output_byte_count": used,
        "retained_bytes_hashed": true,
        "supported_header_and_record_structure_validated": true,
        "capture_origin_verified": false,
        "capture_clock_verified": false,
        "complete_capture_interval_verified": false,
        "packet_checksum_or_offload_verified": false,
        "physical_wire_frame_size_verified": false,
        "delivery_verified": false,
        "statistical_independence_proven": false,
        "full_leak_audit_capture_decoded": false,
        "runtime_policy_applied": false,
        "beta_exit": false
    });
    Ok(Converted {
        tsv: output,
        summary,
    })
}

fn be16(bytes: &[u8]) -> u16 {
    u16::from_be_bytes([bytes[0], bytes[1]])
}
fn packet_fields(link: u32, frame: &[u8]) -> Result<Fields, &'static str> {
    let packet = if link == 1 {
        if frame.len() < 14 {
            return Err("Ethernet header is partial");
        }
        let mut ether_type = be16(&frame[12..14]);
        let mut offset = 14;
        let mut tags = 0;
        while [0x8100, 0x88a8].contains(&ether_type) {
            tags += 1;
            if tags > 2 {
                return Err("Ethernet VLAN nesting is unsupported");
            }
            let tag = frame
                .get(offset..offset + 4)
                .ok_or("Ethernet VLAN header is partial")?;
            ether_type = be16(&tag[2..4]);
            offset += 4;
        }
        let packet = &frame[offset..];
        if !matches!(
            (ether_type, packet.first().map(|byte| byte >> 4)),
            (0x0800, Some(4)) | (0x86dd, Some(6))
        ) {
            return Err("only matching Ethernet IPv4/IPv6 TCP/UDP trial records are supported");
        }
        packet
    } else {
        frame
    };
    let (source, destination, protocol, transport, ip_length) =
        match packet.first().map(|byte| byte >> 4) {
            Some(4) => {
                if packet.len() < 20 {
                    return Err("IPv4 header is partial");
                }
                let header = usize::from(packet[0] & 15) * 4;
                let length = usize::from(be16(&packet[2..4]));
                if header < 20 || length < header || length > packet.len() {
                    return Err("IPv4 declared lengths are invalid or partial");
                }
                if be16(&packet[6..8]) & 0xbfff != 0 {
                    return Err("IPv4 fragments or reserved flags are unsupported");
                }
                (
                    IpAddr::V4(Ipv4Addr::new(
                        packet[12], packet[13], packet[14], packet[15],
                    )),
                    IpAddr::V4(Ipv4Addr::new(
                        packet[16], packet[17], packet[18], packet[19],
                    )),
                    packet[9],
                    &packet[header..length],
                    length,
                )
            }
            Some(6) => {
                if packet.len() < 40 {
                    return Err("IPv6 header is partial");
                }
                let payload = usize::from(be16(&packet[4..6]));
                let length = 40 + payload;
                if payload == 0 || length > packet.len() {
                    return Err("IPv6 jumbograms or partial payloads are unsupported");
                }
                (
                    IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&packet[8..24]).unwrap(),
                    )),
                    IpAddr::V6(Ipv6Addr::from(
                        <[u8; 16]>::try_from(&packet[24..40]).unwrap(),
                    )),
                    packet[6],
                    &packet[40..length],
                    length,
                )
            }
            _ => return Err("unsupported IP version"),
        };
    // Ethernet padding stays in the captured frame length. Raw IP cannot carry
    // unexplained trailing bytes. Neither path attests offload/checksum validity.
    if link == 101 && ip_length != packet.len() {
        return Err("raw IP record has unexplained trailing bytes");
    }
    let protocol = match protocol {
        6 => {
            if transport.len() < 20 {
                return Err("TCP header is partial");
            }
            let header = usize::from(transport[12] >> 4) * 4;
            if header < 20 || header > transport.len() {
                return Err("TCP header length is invalid or partial");
            }
            "tcp"
        }
        17 => {
            if transport.len() < 8 || usize::from(be16(&transport[4..6])) != transport.len() {
                return Err("UDP header or declared length is invalid or partial");
            }
            "udp"
        }
        _ => return Err("IP fragments, extensions and non-TCP/UDP trial records are unsupported"),
    };
    let source_port = be16(&transport[..2]);
    let destination_port = be16(&transport[2..4]);
    if source_port == 0
        || destination_port == 0
        || source == destination && source_port == destination_port
    {
        return Err("TCP/UDP trial endpoints must be nonzero and distinct");
    }
    Ok(Fields {
        source,
        destination,
        protocol,
        source_port,
        destination_port,
    })
}

#[cfg(test)]
#[path = "privacy_pcap/tests.rs"]
mod tests;
