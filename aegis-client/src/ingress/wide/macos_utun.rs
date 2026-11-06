//! macOS packet source for the shared TCP/UDP relay engine.
//! This module does not install routes or alter the system firewall.
use super::ip_tunnel::PacketIo;
use std::{
    ffi::CString,
    io, mem,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
};
const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;
#[repr(C)]
struct CtlInfo {
    id: u32,
    name: [libc::c_char; 96],
}
#[repr(C)]
struct SockaddrCtl {
    len: u8,
    family: u8,
    sysaddr: u16,
    id: u32,
    unit: u32,
    reserved: [u32; 5],
}
pub(crate) struct Utun {
    fd: OwnedFd,
    pub name: String,
}
impl Utun {
    pub fn open() -> io::Result<Self> {
        let raw = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, 2) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut info = CtlInfo {
            id: 0,
            name: [0; 96],
        };
        let name = CString::new("com.apple.net.utun_control").unwrap();
        for (dst, src) in info.name.iter_mut().zip(name.as_bytes_with_nul()) {
            *dst = *src as libc::c_char;
        }
        if unsafe { libc::ioctl(raw, CTLIOCGINFO, &mut info) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let address = SockaddrCtl {
            len: mem::size_of::<SockaddrCtl>() as u8,
            family: libc::AF_SYSTEM as u8,
            sysaddr: 2,
            id: info.id,
            unit: 0,
            reserved: [0; 5],
        };
        if unsafe {
            libc::connect(
                raw,
                (&address as *const SockaddrCtl).cast(),
                mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = [0u8; 64];
        let mut len = bytes.len() as libc::socklen_t;
        if unsafe { libc::getsockopt(raw, 2, 2, bytes.as_mut_ptr().cast(), &mut len) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = bytes
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| io::Error::other("unterminated utun name"))?;
        let name = std::str::from_utf8(&bytes[..end])
            .map_err(io::Error::other)?
            .to_owned();
        if !name
            .strip_prefix("utun")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(io::Error::other("unexpected utun interface name"));
        }
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            || unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd, name })
    }
}
fn decode_frame(bytes: &[u8]) -> io::Result<&[u8]> {
    if bytes.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "short utun frame",
        ));
    }
    let family = u32::from_be_bytes(bytes[..4].try_into().unwrap());
    let version = bytes[4] >> 4;
    if !((family == libc::AF_INET as u32 && version == 4)
        || (family == libc::AF_INET6 as u32 && version == 6))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "utun family/version mismatch",
        ));
    }
    Ok(&bytes[4..])
}
fn encode_frame(packet: &[u8]) -> io::Result<Vec<u8>> {
    let family = match packet.first().map(|b| b >> 4) {
        Some(4) => libc::AF_INET,
        Some(6) => libc::AF_INET6,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid IP packet",
            ))
        }
    };
    let mut bytes = Vec::with_capacity(packet.len() + 4);
    bytes.extend_from_slice(&(family as u32).to_be_bytes());
    bytes.extend_from_slice(packet);
    Ok(bytes)
}
impl PacketIo for Utun {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let mut frame = vec![0; 65540];
        let size =
            unsafe { libc::read(self.fd.as_raw_fd(), frame.as_mut_ptr().cast(), frame.len()) };
        if size < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(error)
            };
        }
        if size == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        Ok(Some(decode_frame(&frame[..size as usize])?.to_vec()))
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        let frame = encode_frame(packet)?;
        let size = unsafe { libc::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        if size as usize != frame.len() {
            return Err(io::ErrorKind::WriteZero.into());
        }
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn frame_roundtrip_and_reject_mismatched_family() {
        for version in [4, 6] {
            let packet = vec![version << 4, 0, 0, 0];
            let encoded = encode_frame(&packet).unwrap();
            assert_eq!(decode_frame(&encoded).unwrap(), packet);
        }
        let mut frame = encode_frame(&[0x60, 0, 0, 0]).unwrap();
        frame[..4].copy_from_slice(&(libc::AF_INET as u32).to_be_bytes());
        assert!(decode_frame(&frame).is_err());
        assert!(decode_frame(&[0; 4]).is_err());
        assert!(encode_frame(&[]).is_err());
    }
}
