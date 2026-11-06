//! Strict NFQUEUE datagram decoding for relay outer packets.
//! The Linux recvmsg caller additionally checks kernel sockaddr_nl sender and
//! MSG_TRUNC. No malformed or unknown packet can produce an ACCEPT verdict.
use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hook {
    Input,
    PostRouting,
}
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    Frame,
    Ownership,
    Offload,
    KernelError,
}
#[derive(Debug, PartialEq, Eq)]
pub struct QueuedPacket<'a> {
    pub id: u32,
    pub payload: &'a [u8],
    pub checksum_pending: bool,
}
#[derive(Clone, Copy)]
pub struct QueuePin {
    pub queue: u16,
    pub sequence: u32,
    pub mark: u32,
    pub interface: u32,
    pub hook: Hook,
}
fn be32(b: &[u8]) -> Result<u32, DecodeError> {
    Ok(u32::from_be_bytes(
        b.try_into().map_err(|_| DecodeError::Frame)?,
    ))
}
fn aligned(n: usize) -> Option<usize> {
    n.checked_add(3).map(|n| n & !3)
}

pub fn decode<'a>(
    datagram: &'a [u8],
    kernel_pid: u32,
    truncated: bool,
    pin: QueuePin,
) -> Result<QueuedPacket<'a>, DecodeError> {
    if kernel_pid != 0
        || truncated
        || pin.mark == 0
        || pin.interface == 0
        || datagram.len() < 20
        || datagram.len() > 131072
    {
        return Err(DecodeError::Ownership);
    }
    let length = u32::from_ne_bytes(datagram[0..4].try_into().unwrap()) as usize;
    let kind = u16::from_ne_bytes(datagram[4..6].try_into().unwrap());
    let flags = u16::from_ne_bytes(datagram[6..8].try_into().unwrap());
    let sequence = u32::from_ne_bytes(datagram[8..12].try_into().unwrap());
    let sender = u32::from_ne_bytes(datagram[12..16].try_into().unwrap());
    // One packet per datagram, exact family/version/resource and kernel sender.
    if length != datagram.len()
        || flags != 0
        || kind != 0x0300
        || sequence != pin.sequence
        || sender != 0
        || datagram[16] != 2
        || datagram[17] != 0
        || datagram[18..20] != pin.queue.to_be_bytes()
    {
        return Err(if kind == 2 {
            DecodeError::KernelError
        } else {
            DecodeError::Ownership
        });
    }
    let mut attrs = BTreeMap::new();
    let mut offset = 20usize;
    while offset < length {
        let hdr = datagram.get(offset..offset + 4).ok_or(DecodeError::Frame)?;
        let len = usize::from(u16::from_ne_bytes(hdr[0..2].try_into().unwrap()));
        let kind = u16::from_ne_bytes(hdr[2..4].try_into().unwrap());
        if len < 4 || kind & 0xc000 != 0 {
            return Err(DecodeError::Frame);
        }
        let end = offset.checked_add(len).ok_or(DecodeError::Frame)?;
        let data = datagram.get(offset + 4..end).ok_or(DecodeError::Frame)?;
        if attrs.insert(kind, data).is_some() {
            return Err(DecodeError::Frame);
        }
        // Kernel NFQA_PAYLOAD is the last attribute and skb->len may omit
        // its trailing alignment padding. Exact final data is still complete.
        offset = if end == length {
            length
        } else {
            offset
                .checked_add(aligned(len).ok_or(DecodeError::Frame)?)
                .ok_or(DecodeError::Frame)?
        };
        if offset > length {
            return Err(DecodeError::Frame);
        }
    }
    let header = attrs.get(&1).ok_or(DecodeError::Frame)?;
    if header.len() != 7 || header[4..6] != [8, 0] {
        return Err(DecodeError::Frame);
    }
    let hook = match pin.hook {
        Hook::Input => 1,
        Hook::PostRouting => 4,
    };
    if header[6] != hook {
        return Err(DecodeError::Ownership);
    }
    if be32(attrs.get(&3).ok_or(DecodeError::Ownership)?)? != pin.mark {
        return Err(DecodeError::Ownership);
    }
    let index = match pin.hook {
        Hook::Input => 5,
        Hook::PostRouting => 6,
    };
    if be32(attrs.get(&index).ok_or(DecodeError::Ownership)?)? != pin.interface {
        return Err(DecodeError::Ownership);
    }
    // NFQA_SKB_INFO: never process a GSO superpacket. Pending transport
    // checksum must be completed from the full original before the program.
    let checksum_pending = if let Some(info) = attrs.get(&14) {
        let flags = be32(info)?;
        if flags & !5 != 0 {
            return Err(DecodeError::Offload);
        }
        flags & 1 != 0
    } else {
        false
    };
    let payload = *attrs.get(&10).ok_or(DecodeError::Frame)?;
    if payload.len() < 20 || payload.len() > 65535 {
        return Err(DecodeError::Frame);
    }
    if let Some(cap_len) = attrs.get(&13) {
        if be32(cap_len)? as usize != payload.len() {
            return Err(DecodeError::Frame);
        }
    }
    Ok(QueuedPacket {
        id: be32(&header[..4])?,
        payload,
        checksum_pending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn pin() -> QueuePin {
        QueuePin {
            queue: 414,
            sequence: 0,
            mark: 0xae9_u32,
            interface: 7,
            hook: Hook::PostRouting,
        }
    }
    fn attr(b: &mut Vec<u8>, kind: u16, data: &[u8]) {
        b.extend_from_slice(&((data.len() + 4) as u16).to_ne_bytes());
        b.extend_from_slice(&kind.to_ne_bytes());
        b.extend_from_slice(data);
        while !b.len().is_multiple_of(4) {
            b.push(0)
        }
    }
    fn packet() -> Vec<u8> {
        let p = pin();
        let mut b = vec![0u8; 20];
        b[4..6].copy_from_slice(&0x300u16.to_ne_bytes());
        b[16] = 2;
        b[18..20].copy_from_slice(&p.queue.to_be_bytes());
        attr(&mut b, 1, &[0, 0, 0, 9, 8, 0, 4]);
        attr(&mut b, 3, &p.mark.to_be_bytes());
        attr(&mut b, 6, &p.interface.to_be_bytes());
        attr(&mut b, 10, &[0u8; 20]);
        let len = b.len() as u32;
        b[..4].copy_from_slice(&len.to_ne_bytes());
        b
    }
    #[test]
    fn exact_kernel_frame_decodes_id_without_accept_verdict() {
        let b = packet();
        assert_eq!(decode(&b, 0, false, pin()).unwrap().id, 9);
    }
    #[test]
    fn wrong_sender_hook_queue_mark_interface_refused() {
        let b = packet();
        assert!(decode(&b, 1, false, pin()).is_err());
        assert!(decode(&b, 0, true, pin()).is_err());
        for offset in [6usize, 8, 12, 16, 17, 18, 30, 35, 43, 51] {
            let mut bad = b.clone();
            bad[offset] ^= 1;
            assert!(decode(&bad, 0, false, pin()).is_err(), "{offset}");
        }
        let mut p = pin();
        p.hook = Hook::Input;
        assert!(decode(&b, 0, false, p).is_err());
    }
    #[test]
    fn offload_duplicate_and_partial_copies_refused() {
        for (kind, data) in [
            (14, 8u32.to_be_bytes()),
            (14, 2u32.to_be_bytes()),
            (13, 21u32.to_be_bytes()),
            (3, pin().mark.to_be_bytes()),
        ] {
            let mut b = packet();
            attr(&mut b, kind, &data);
            let len = b.len() as u32;
            b[..4].copy_from_slice(&len.to_ne_bytes());
            assert!(decode(&b, 0, false, pin()).is_err());
        }
    }
}

#[cfg(test)]
mod kernel_uapi_tests {
    use super::*;
    // Linux UAPI nfnetlink_queue.h places TIMESTAMP=4 before INDEV=5,
    // OUTDEV=6. This fixture is independent from Hook/index generation.
    #[test]
    fn timestamp_is_not_a_device_index_and_outdev_is_six() {
        fn nla(b: &mut Vec<u8>, kind: u16, data: &[u8]) {
            b.extend_from_slice(&((data.len() + 4) as u16).to_ne_bytes());
            b.extend_from_slice(&kind.to_ne_bytes());
            b.extend_from_slice(data);
            while !b.len().is_multiple_of(4) {
                b.push(0)
            }
        }
        let mut b = vec![0; 20];
        b[4..6].copy_from_slice(&0x300u16.to_ne_bytes());
        b[16] = 2;
        b[18..20].copy_from_slice(&414u16.to_be_bytes());
        nla(&mut b, 1, &[0, 0, 0, 9, 8, 0, 4]);
        nla(&mut b, 3, &0xae9u32.to_be_bytes());
        nla(&mut b, 4, &[0; 16]);
        nla(&mut b, 6, &7u32.to_be_bytes());
        nla(&mut b, 10, &[0; 20]);
        let len = b.len() as u32;
        b[..4].copy_from_slice(&len.to_ne_bytes());
        let pin = QueuePin {
            queue: 414,
            sequence: 0,
            mark: 0xae9,
            interface: 7,
            hook: Hook::PostRouting,
        };
        assert_eq!(decode(&b, 0, false, pin).unwrap().id, 9);
        let mut pin = pin;
        pin.hook = Hook::Input;
        assert!(decode(&b, 0, false, pin).is_err());
    }
}

#[cfg(test)]
mod kernel_payload_tests {
    use super::*;
    #[test]
    fn genuine_last_payload_without_alignment_padding_is_complete() {
        let mut b = vec![0; 20];
        b[4..6].copy_from_slice(&0x300u16.to_ne_bytes());
        b[16] = 2;
        b[18..20].copy_from_slice(&414u16.to_be_bytes());
        fn a(b: &mut Vec<u8>, kind: u16, data: &[u8], pad: bool) {
            b.extend_from_slice(&((data.len() + 4) as u16).to_ne_bytes());
            b.extend_from_slice(&kind.to_ne_bytes());
            b.extend_from_slice(data);
            if pad {
                while !b.len().is_multiple_of(4) {
                    b.push(0)
                }
            }
        }
        a(&mut b, 1, &[0, 0, 0, 9, 8, 0, 4], true);
        a(&mut b, 3, &0xae9u32.to_be_bytes(), true);
        a(&mut b, 6, &7u32.to_be_bytes(), true);
        a(&mut b, 10, &[0; 21], false);
        let n = b.len() as u32;
        b[..4].copy_from_slice(&n.to_ne_bytes());
        let pin = QueuePin {
            queue: 414,
            sequence: 0,
            mark: 0xae9,
            interface: 7,
            hook: Hook::PostRouting,
        };
        assert_eq!(decode(&b, 0, false, pin).unwrap().payload.len(), 21);
        b.pop();
        let n = b.len() as u32;
        b[..4].copy_from_slice(&n.to_ne_bytes());
        assert!(decode(&b, 0, false, pin).is_err());
    }
}
