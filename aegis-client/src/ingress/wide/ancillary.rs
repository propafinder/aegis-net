//! Bounded ancillary-message decoding. Runtime users are Linux recvmsg paths;
//! pure tests also run on Unix development hosts with that host's libc layout.

use std::io;
use std::mem::size_of;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

/// The zero-length header supplies the native control-message alignment without
/// interpreting byte storage as a Rust reference to a C structure.
#[repr(C)]
pub(super) struct ControlBuffer<const N: usize> {
    alignment: [libc::cmsghdr; 0],
    bytes: [u8; N],
}

impl<const N: usize> ControlBuffer<N> {
    pub(super) fn new() -> Self {
        Self {
            alignment: [],
            bytes: [0; N],
        }
    }

    pub(super) fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        self.bytes.as_mut_ptr().cast()
    }

    pub(super) fn len(&self) -> usize {
        N
    }

    pub(super) fn received(&self, length: usize, flags: libc::c_int) -> io::Result<&[u8]> {
        if flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 {
            return Err(invalid("truncated UDP payload or ancillary message"));
        }
        self.bytes
            .get(..length)
            .ok_or_else(|| invalid("invalid ancillary buffer length"))
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(super) const fn cmsg_align(len: usize) -> usize {
    let align = size_of::<usize>();
    (len + align - 1) & !(align - 1)
}

pub(super) const fn cmsg_space(len: usize) -> usize {
    cmsg_align(size_of::<libc::cmsghdr>()) + cmsg_align(len)
}

/// Returns bytes only from the current matching cmsg, never from its padding or
/// a subsequent message. No caller alignment or typed-data invariant is needed.
#[allow(clippy::unnecessary_cast)] // glibc usize vs musl socklen_t
fn find_payload(control: &[u8], level: libc::c_int, kind: libc::c_int) -> io::Result<&[u8]> {
    let header_len = cmsg_align(size_of::<libc::cmsghdr>());
    let mut remaining = control;
    while remaining.len() >= size_of::<libc::cmsghdr>() {
        // SAFETY: the slice contains a complete header; libc::cmsghdr consists
        // of integers, so all initialized byte patterns are valid. The copy
        // deliberately makes no alignment assumption about the input slice.
        let header = unsafe { remaining.as_ptr().cast::<libc::cmsghdr>().read_unaligned() };
        let length = header.cmsg_len as usize;
        if length < header_len || length > remaining.len() {
            return Err(invalid(
                "malformed UDP original-destination control message",
            ));
        }
        if header.cmsg_level == level && header.cmsg_type == kind {
            return Ok(&remaining[header_len..length]);
        }
        let advance = length
            .checked_add(size_of::<usize>() - 1)
            .map(|length| length & !(size_of::<usize>() - 1))
            .ok_or_else(|| invalid("ancillary message length overflow"))?;
        // The last message need not include trailing alignment padding.
        remaining = remaining.get(advance..).unwrap_or_default();
    }
    Err(io::Error::new(
        io::ErrorKind::NotFound,
        "missing original-destination control message",
    ))
}

pub(super) fn original_destination_v4(
    control: &[u8],
    level: libc::c_int,
    kind: libc::c_int,
) -> io::Result<SocketAddrV4> {
    let payload = find_payload(control, level, kind)?;
    if payload.len() < size_of::<libc::sockaddr_in>() {
        return Err(invalid("short IP_ORIGDSTADDR control message"));
    }
    // SAFETY: the checked current cmsg payload contains the complete integer-
    // only sockaddr_in layout. read_unaligned creates an owned value, no
    // reference into the possibly unaligned byte slice.
    let addr = unsafe {
        payload
            .as_ptr()
            .cast::<libc::sockaddr_in>()
            .read_unaligned()
    };
    if addr.sin_family as libc::c_int != libc::AF_INET {
        return Err(invalid("IP_ORIGDSTADDR address family is not IPv4"));
    }
    Ok(SocketAddrV4::new(
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

pub(super) fn original_destination_v6(
    control: &[u8],
    level: libc::c_int,
    kind: libc::c_int,
) -> io::Result<SocketAddrV6> {
    let payload = find_payload(control, level, kind)?;
    if payload.len() < size_of::<libc::sockaddr_in6>() {
        return Err(invalid("short IPV6_ORIGDSTADDR control message"));
    }
    // SAFETY: as above, with a complete integer-only sockaddr_in6 value.
    let addr = unsafe {
        payload
            .as_ptr()
            .cast::<libc::sockaddr_in6>()
            .read_unaligned()
    };
    if addr.sin6_family as libc::c_int != libc::AF_INET6 {
        return Err(invalid("IPV6_ORIGDSTADDR address family is not IPv6"));
    }
    Ok(SocketAddrV6::new(
        Ipv6Addr::from(addr.sin6_addr.s6_addr),
        u16::from_be(addr.sin6_port),
        addr.sin6_flowinfo,
        addr.sin6_scope_id,
    ))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use std::mem::{align_of, offset_of};

    fn put(control: &mut [u8], offset: usize, bytes: &[u8]) {
        control[offset..offset + bytes.len()].copy_from_slice(bytes);
    }

    fn control(payload_len: usize, level: libc::c_int, kind: libc::c_int) -> Vec<u8> {
        let mut bytes = vec![0; cmsg_space(payload_len)];
        let header = libc::cmsghdr {
            cmsg_len: (cmsg_align(size_of::<libc::cmsghdr>()) + payload_len) as _,
            cmsg_level: level,
            cmsg_type: kind,
        };
        put(
            &mut bytes,
            offset_of!(libc::cmsghdr, cmsg_len),
            &header.cmsg_len.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(libc::cmsghdr, cmsg_level),
            &level.to_ne_bytes(),
        );
        put(
            &mut bytes,
            offset_of!(libc::cmsghdr, cmsg_type),
            &kind.to_ne_bytes(),
        );
        bytes
    }

    pub(crate) fn control_v4(dst: SocketAddrV4, level: libc::c_int, kind: libc::c_int) -> Vec<u8> {
        let mut bytes = control(size_of::<libc::sockaddr_in>(), level, kind);
        let base = cmsg_align(size_of::<libc::cmsghdr>());
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in, sin_family),
            &(libc::AF_INET as libc::sa_family_t).to_ne_bytes(),
        );
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in, sin_port),
            &dst.port().to_be_bytes(),
        );
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in, sin_addr),
            &dst.ip().octets(),
        );
        bytes
    }

    pub(crate) fn control_v6(dst: SocketAddrV6, level: libc::c_int, kind: libc::c_int) -> Vec<u8> {
        let mut bytes = control(size_of::<libc::sockaddr_in6>(), level, kind);
        let base = cmsg_align(size_of::<libc::cmsghdr>());
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in6, sin6_family),
            &(libc::AF_INET6 as libc::sa_family_t).to_ne_bytes(),
        );
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in6, sin6_port),
            &dst.port().to_be_bytes(),
        );
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in6, sin6_addr),
            &dst.ip().octets(),
        );
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in6, sin6_flowinfo),
            &dst.flowinfo().to_ne_bytes(),
        );
        put(
            &mut bytes,
            base + offset_of!(libc::sockaddr_in6, sin6_scope_id),
            &dst.scope_id().to_ne_bytes(),
        );
        bytes
    }

    #[test]
    fn recv_buffer_has_native_header_alignment_and_bounds() {
        let mut buffer = ControlBuffer::<128>::new();
        assert_eq!(
            buffer.as_mut_ptr() as usize % align_of::<libc::cmsghdr>(),
            0
        );
        assert_eq!(buffer.received(buffer.len(), 0).unwrap().len(), 128);
        assert!(buffer.received(129, 0).is_err());
        assert!(buffer.received(0, libc::MSG_CTRUNC).is_err());
        assert!(buffer.received(0, libc::MSG_TRUNC).is_err());
    }

    #[test]
    fn destination_parsers_accept_every_input_alignment() {
        let v4 = "192.0.2.17:5353".parse().unwrap();
        let v6 = SocketAddrV6::new("2001:db8::17".parse().unwrap(), 5353, 7, 9);
        for padding in 0..align_of::<libc::cmsghdr>() {
            let mut bytes = vec![0; padding];
            bytes.extend(control_v4(v4, 1, 20));
            assert_eq!(
                original_destination_v4(&bytes[padding..], 1, 20).unwrap(),
                v4
            );
            let mut bytes = vec![0; padding];
            bytes.extend(control_v6(v6, 41, 74));
            assert_eq!(
                original_destination_v6(&bytes[padding..], 41, 74).unwrap(),
                v6
            );
        }
    }

    #[test]
    fn current_cmsg_bounds_exclude_following_payload() {
        let v4 = "192.0.2.17:5353".parse().unwrap();
        let v6 = "[2001:db8::17]:5353".parse().unwrap();
        for short in 0..size_of::<libc::sockaddr_in>() {
            let mut bytes = control(short, 1, 20);
            bytes.extend(control_v4(v4, 1, 20));
            assert_eq!(
                original_destination_v4(&bytes, 1, 20).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
        for short in 0..size_of::<libc::sockaddr_in6>() {
            let mut bytes = control(short, 41, 74);
            bytes.extend(control_v6(v6, 41, 74));
            assert_eq!(
                original_destination_v6(&bytes, 41, 74).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn messages_are_bounded_and_wrong_families_rejected() {
        let v4 = "192.0.2.17:5353".parse().unwrap();
        let valid = control_v4(v4, 1, 20);
        for end in 0..cmsg_align(size_of::<libc::cmsghdr>()) + size_of::<libc::sockaddr_in>() {
            assert!(original_destination_v4(&valid[..end], 1, 20).is_err());
        }
        let mut bytes = control(3, 99, 99);
        bytes.extend_from_slice(&valid);
        assert_eq!(original_destination_v4(&bytes, 1, 20).unwrap(), v4);
        let mut wrong = valid;
        put(
            &mut wrong,
            cmsg_align(size_of::<libc::cmsghdr>()) + offset_of!(libc::sockaddr_in, sin_family),
            &(libc::AF_INET6 as libc::sa_family_t).to_ne_bytes(),
        );
        assert!(original_destination_v4(&wrong, 1, 20).is_err());
        let mut malformed = control(0, 1, 20);
        // Zero length is invalid even when a full header is present.
        let size = size_of_val(
            &libc::cmsghdr {
                cmsg_len: 0,
                cmsg_level: 0,
                cmsg_type: 0,
            }
            .cmsg_len,
        );
        malformed[offset_of!(libc::cmsghdr, cmsg_len)..offset_of!(libc::cmsghdr, cmsg_len) + size]
            .fill(0);
        assert!(original_destination_v4(&malformed, 1, 20).is_err());
    }
}
