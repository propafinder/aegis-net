//! Bounded IP fragmentation boundary. No transport tuple is consumed until a
//! complete, non-overlapping datagram exists. Both directions support IPv6.
use std::net::IpAddr;
use std::{
    collections::HashMap,
    io,
    time::{Duration, Instant},
};
#[derive(Clone, Hash, Eq, PartialEq)]
struct Key {
    source: Vec<u8>,
    destination: Vec<u8>,
    id: u32,
    protocol: u8,
}
struct Assembly {
    created: Instant,
    header: Option<Vec<u8>>,
    parts: Vec<(usize, Vec<u8>)>,
    length: Option<usize>,
}
#[derive(Default)]
pub(super) struct Fragments {
    pending: HashMap<Key, Assembly>,
}
fn invalid() -> io::Error {
    io::ErrorKind::InvalidData.into()
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in bytes.chunks(2) {
        sum += u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]) as u32;
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
impl Fragments {
    pub fn accept(&mut self, packet: &[u8]) -> io::Result<Option<Vec<u8>>> {
        self.pending
            .retain(|_, a| a.created.elapsed() < Duration::from_secs(15));
        let version = packet.first().ok_or_else(invalid)? >> 4;
        let (key, offset, more, payload, header) = match version {
            4 => {
                if packet.len() < 20 {
                    return Err(invalid());
                }
                let h = (packet[0] & 15) as usize * 4;
                if h < 20
                    || h > packet.len()
                    || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
                    || checksum(&packet[..h]) != 0
                {
                    return Err(invalid());
                }
                let flags = u16::from_be_bytes([packet[6], packet[7]]);
                if flags & 0x8000 != 0 {
                    return Err(invalid());
                }
                if flags & 0x3fff == 0 {
                    return Ok(Some(packet.to_vec()));
                }
                if flags & 0x4000 != 0 {
                    return Err(invalid());
                }
                (
                    Key {
                        source: packet[12..16].to_vec(),
                        destination: packet[16..20].to_vec(),
                        id: u16::from_be_bytes([packet[4], packet[5]]) as u32,
                        protocol: packet[9],
                    },
                    (flags as usize & 8191) * 8,
                    flags & 0x2000 != 0,
                    &packet[h..],
                    packet[..h].to_vec(),
                )
            }
            6 => {
                if packet.len() < 40
                    || usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 != packet.len()
                {
                    return Err(invalid());
                }
                let mut next = packet[6];
                let mut previous = 6;
                let mut offset = 40;
                for _ in 0..8 {
                    if next == 44 {
                        break;
                    }
                    if ![0, 43, 60].contains(&next) {
                        return Ok(Some(packet.to_vec()));
                    }
                    if offset + 2 > packet.len() {
                        return Err(invalid());
                    }
                    let length = (packet[offset + 1] as usize + 1) * 8;
                    if offset + length > packet.len() {
                        return Err(invalid());
                    }
                    previous = offset;
                    next = packet[offset];
                    offset += length;
                }
                if next != 44 || offset + 8 > packet.len() {
                    return Err(invalid());
                }
                let bits = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]);
                if bits & 6 != 0 || packet[offset + 1] != 0 {
                    return Err(invalid());
                }
                let mut header = packet[..offset].to_vec();
                header[previous] = packet[offset];
                (
                    Key {
                        source: packet[8..24].to_vec(),
                        destination: packet[24..40].to_vec(),
                        id: u32::from_be_bytes(packet[offset + 4..offset + 8].try_into().unwrap()),
                        protocol: packet[offset],
                    },
                    (bits & 0xfff8) as usize,
                    bits & 1 != 0,
                    &packet[offset + 8..],
                    header,
                )
            }
            _ => return Err(invalid()),
        };
        if payload.is_empty()
            || more && payload.len() % 8 != 0
            || offset + payload.len() + header.len() > if version == 6 { 65575 } else { 65535 }
        {
            return Err(invalid());
        }
        if !self.pending.contains_key(&key) && self.pending.len() >= 64 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let a = self.pending.entry(key.clone()).or_insert_with(|| Assembly {
            created: Instant::now(),
            header: None,
            parts: vec![],
            length: None,
        });
        if a.parts.len() >= 128
            || a.parts
                .iter()
                .any(|(start, p)| offset < start + p.len() && *start < offset + payload.len())
            || a.length.is_some_and(|n| offset + payload.len() > n)
        {
            // Poison this ID until expiry. Later fragments cannot resurrect a
            // partially rejected datagram and mix it with another generation.
            a.parts.clear();
            a.length = Some(0);
            return Err(invalid());
        }
        if !more {
            if a.length.is_some_and(|n| n != offset + payload.len())
                || a.parts
                    .iter()
                    .any(|(start, p)| start + p.len() > offset + payload.len())
            {
                a.parts.clear();
                a.length = Some(0);
                return Err(invalid());
            }
            a.length = Some(offset + payload.len());
        }
        if offset == 0 {
            a.header = Some(header);
        }
        a.parts.push((offset, payload.to_vec()));
        a.parts.sort_by_key(|p| p.0);
        let Some(length) = a.length else {
            return Ok(None);
        };
        let mut cursor = 0;
        for (offset, p) in &a.parts {
            if *offset != cursor {
                return Ok(None);
            }
            cursor += p.len();
        }
        if cursor != length || a.header.is_none() {
            return Ok(None);
        }
        let mut output = a.header.take().unwrap();
        for (_, p) in &a.parts {
            output.extend_from_slice(p);
        }
        if version == 4 {
            let n = output.len() as u16;
            output[2..4].copy_from_slice(&n.to_be_bytes());
            output[6..8].fill(0);
            output[10..12].fill(0);
            let h = (output[0] & 15) as usize * 4;
            let check = checksum(&output[..h]);
            output[10..12].copy_from_slice(&check.to_be_bytes());
        } else {
            let n = (output.len() - 40) as u16;
            output[4..6].copy_from_slice(&n.to_be_bytes());
        }
        self.pending.remove(&key);
        Ok(Some(output))
    }
}

pub(super) fn udp_packets(
    source: IpAddr,
    source_port: u16,
    destination: IpAddr,
    destination_port: u16,
    payload: &[u8],
    mtu: usize,
) -> io::Result<Vec<Vec<u8>>> {
    if payload.len() > 65507 || source.is_ipv4() != destination.is_ipv4() || mtu < 1280 {
        return Err(invalid());
    }
    let n = (payload.len() + 8) as u16;
    let mut udp = vec![0; 8];
    udp[..2].copy_from_slice(&source_port.to_be_bytes());
    udp[2..4].copy_from_slice(&destination_port.to_be_bytes());
    udp[4..6].copy_from_slice(&n.to_be_bytes());
    udp.extend_from_slice(payload);
    let mut pseudo = vec![];
    match (source, destination) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&n.to_be_bytes());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            pseudo.extend_from_slice(&s.octets());
            pseudo.extend_from_slice(&d.octets());
            pseudo.extend_from_slice(&(n as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
        }
        _ => return Err(invalid()),
    }
    pseudo.extend_from_slice(&udp);
    let c = checksum(&pseudo);
    udp[6..8].copy_from_slice(&if c == 0 { 65535u16 } else { c }.to_be_bytes());
    let mut packets = vec![];
    match (source, destination) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            let id = rand::random::<u16>();
            let chunk = (mtu - 20) / 8 * 8;
            for (i, part) in udp.chunks(chunk).enumerate() {
                let offset = i * chunk;
                let more = offset + part.len() < udp.len();
                let mut p = vec![0; 20];
                p[0] = 0x45;
                p[2..4].copy_from_slice(&((20 + part.len()) as u16).to_be_bytes());
                p[4..6].copy_from_slice(&id.to_be_bytes());
                p[6..8].copy_from_slice(
                    &((offset / 8) as u16 | if more { 0x2000 } else { 0 }).to_be_bytes(),
                );
                p[8] = 64;
                p[9] = 17;
                p[12..16].copy_from_slice(&s.octets());
                p[16..20].copy_from_slice(&d.octets());
                let c = checksum(&p);
                p[10..12].copy_from_slice(&c.to_be_bytes());
                p.extend_from_slice(part);
                packets.push(p);
            }
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            let fragmented = udp.len() + 40 > mtu;
            let id = rand::random::<u32>();
            let chunk = if fragmented {
                (mtu - 48) / 8 * 8
            } else {
                udp.len()
            };
            for (i, part) in udp.chunks(chunk).enumerate() {
                let offset = i * chunk;
                let mut p = vec![0; 40];
                p[0] = 0x60;
                p[4..6].copy_from_slice(
                    &((part.len() + if fragmented { 8 } else { 0 }) as u16).to_be_bytes(),
                );
                p[6] = if fragmented { 44 } else { 17 };
                p[7] = 64;
                p[8..24].copy_from_slice(&s.octets());
                p[24..40].copy_from_slice(&d.octets());
                if fragmented {
                    p.extend_from_slice(&[17, 0]);
                    p.extend_from_slice(
                        &((offset as u16) | u16::from(offset + part.len() < udp.len()))
                            .to_be_bytes(),
                    );
                    p.extend_from_slice(&id.to_be_bytes());
                }
                p.extend_from_slice(part);
                packets.push(p);
            }
        }
        _ => return Err(invalid()),
    }
    Ok(packets)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reordered_large_datagrams_and_overlap_rejection() {
        for (s, d) in [("198.19.255.1", "1.1.1.1"), ("fd00:ae61::1", "2001:db8::2")] {
            let data = vec![173; 65000];
            let packets = udp_packets(
                s.parse().unwrap(),
                12000,
                d.parse().unwrap(),
                443,
                &data,
                1280,
            )
            .unwrap();
            assert!(packets.len() > 40);
            let mut assembly = Fragments::default();
            let mut whole = None;
            for p in packets.iter().rev() {
                if let Some(p) = assembly.accept(p).unwrap() {
                    whole = Some(p);
                }
            }
            assert!(whole.unwrap().ends_with(&data));
            let mut a = Fragments::default();
            assert!(a.accept(&packets[0]).unwrap().is_none());
            assert!(a.accept(&packets[0]).is_err());
            for p in packets.iter().skip(1) {
                assert!(a.accept(p).is_err());
            }
        }
    }
}
