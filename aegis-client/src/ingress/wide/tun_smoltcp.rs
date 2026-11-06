//! Controlled Linux TUN IPv6 lab (route + packet-observe layer).
//!
//! This is the **controlled lab** foundation for the future TUN + smoltcp IPv6
//! packet-to-relay path (see the archived linux-tun-smoltcp-ipv6-relay-design.md design baseline). It
//! is NOT a production backend and NOT a default route.
//!
//! Scope of THIS layer (no smoltcp yet):
//! - create an AEGIS-owned TUN device (libc TUNSETIFF, non-persistent),
//! - install ONE controlled IPv6 `/128` route into it (never a default route),
//! - keep the relay/server IP on its normal route (excluded from the tun),
//! - read raw IPv6 packets from the device and decode the TCP 5-tuple with the
//!   existing decoder,
//! - RAII cleanup that removes only the AEGIS-owned route + interface.
//!
//! The smoltcp TCP state machine and the relay bridge are later phases; the
//! route/packet layer is independently provable.

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use super::linux_nfqueue::decode_tcp;
use crate::runtime_events::RuntimeEventCode;
use crate::runtime_jsonl;
use serde_json::json;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::process::Command;

const IFF_TUN: i16 = 0x0001;
const IFF_NO_PI: i16 = 0x1000;
// Linux UAPI include/uapi/linux/if_tun.h: refuse an existing interface.
const IFF_TUN_EXCL: u16 = 0x8000;
// TUNSETIFF = _IOW('T', 202, int) — stable across common 64-bit Linux arches.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

pub struct LabOpts {
    /// Controlled destination to route into the TUN, e.g. an IPv6 /128.
    pub dst_v6: std::net::Ipv6Addr,
    /// Relay/server IP that must NOT be routed through the tun (exclusion).
    pub relay_exclude: Option<std::net::IpAddr>,
    pub ifname: String,
    /// Seconds to wait for at least one controlled IPv6 packet.
    pub observe_secs: u64,
}

impl LabOpts {
    pub fn new(dst_v6: std::net::Ipv6Addr) -> Self {
        Self {
            dst_v6,
            relay_exclude: None,
            ifname: "aegis-tun0".to_string(),
            observe_secs: 10,
        }
    }
}

/// An open, AEGIS-owned TUN device. Closing the fd removes the (non-persistent)
/// interface.
pub struct TunDevice {
    fd: OwnedFd,
    pub name: String,
}

impl TunDevice {
    /// Open /dev/net/tun and create a TUN interface with the given name.
    pub fn open(name: &str) -> io::Result<Self> {
        if name.is_empty()
            || name.len() > 15
            || matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid TUN interface name",
            ));
        }
        let raw = unsafe { libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // struct ifreq: 16-byte name, then 16-bit flags.
        let mut ifr = [0u8; 40];
        let bytes = name.as_bytes();
        let n = bytes.len().min(15);
        ifr[..n].copy_from_slice(&bytes[..n]);
        let flags = (IFF_TUN | IFF_NO_PI) as u16 | IFF_TUN_EXCL;
        ifr[16..18].copy_from_slice(&flags.to_ne_bytes());
        // ioctl request type differs by libc (c_ulong on glibc, c_int on musl);
        // `as _` infers the right width. TUNSETIFF (0x400454ca) fits either.
        let rc = unsafe { libc::ioctl(raw, TUNSETIFF as _, ifr.as_mut_ptr()) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // Non-blocking so the observe loop can honour its deadline.
        unsafe {
            let fl = libc::fcntl(raw, libc::F_GETFL);
            if fl < 0 || libc::fcntl(raw, libc::F_SETFL, fl | libc::O_NONBLOCK) < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(Self {
            fd,
            name: name.to_string(),
        })
    }

    /// Raw fd for the smoltcp phy device (lab only; the device owns the fd).
    pub fn raw_fd(&self) -> i32 {
        self.fd.as_raw_fd()
    }

    fn read_packet(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }
}

fn run_ip(args: &[&str]) -> io::Result<bool> {
    Ok(Command::new("ip").args(args).status()?.success())
}

/// RAII guard: removes the controlled /128 route on drop (cleanup never
/// leaves AEGIS-owned routing behind).
struct RouteGuard {
    dst: String,
    ifname: String,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        let _ = run_ip(&["-6", "route", "del", &self.dst, "dev", &self.ifname]);
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideTunSmoltcpCleanupCompleted,
            "wide tun smoltcp cleanup completed",
            json!({ "ifname": self.ifname, "route_removed": self.dst, "scope": "aegis_owned_only" }),
        );
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct LabResult {
    pub device_created: bool,
    pub route_installed: bool,
    pub ipv6_packet_observed: bool,
    pub observed_dst: Option<String>,
    pub default_route_touched: bool,
}

/// Run the controlled IPv6 route+observe lab. Returns the result; emits the
/// lifecycle events. smoltcp / relay bridge are not part of this layer.
pub fn run_route_lab(opts: &LabOpts) -> Result<LabResult, String> {
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpBackendSelected,
        "wide tun smoltcp backend selected (controlled lab; not default route, not production)",
        json!({ "dst_v6": opts.dst_v6.to_string(), "relay_exclude": opts.relay_exclude.map(|x| x.to_string()) }),
    );

    let euid_root = unsafe { libc::geteuid() } == 0;
    let tun_node = std::path::Path::new("/dev/net/tun").exists();
    let ip_present = Command::new("ip")
        .arg("-V")
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpPreflightCompleted,
        "wide tun smoltcp preflight completed",
        json!({ "euid_root": euid_root, "dev_net_tun": tun_node, "ip_tool": ip_present }),
    );
    if !euid_root {
        return Err("BLOCKED_BY_TUN_PRIVILEGE".to_string());
    }
    if !tun_node {
        return Err("BLOCKED_BY_TUN_PRIVILEGE".to_string());
    }
    if !ip_present {
        return Err("BLOCKED_BY_ROUTE_SETUP".to_string());
    }

    let dev =
        TunDevice::open(&opts.ifname).map_err(|e| format!("BLOCKED_BY_TUN_PRIVILEGE: {e}"))?;
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpDeviceCreated,
        "wide tun smoltcp device created",
        json!({ "ifname": dev.name, "non_persistent": true }),
    );

    if !run_ip(&["link", "set", &dev.name, "up"])
        .map_err(|e| format!("BLOCKED_BY_ROUTE_SETUP: {e}"))?
    {
        return Err("BLOCKED_BY_ROUTE_SETUP".to_string());
    }
    // A link-local-ish source on the tun so the kernel has a v6 src for the
    // route. Use a documentation-range /128 host addr on the device.
    let _ = run_ip(&["-6", "addr", "add", "fd00:ae61:5::1/128", "dev", &dev.name]);

    let dst = format!("{}/128", opts.dst_v6);
    // Refuse to install if dst would equal the relay exclusion (defense).
    if let Some(libc_excl) = opts.relay_exclude {
        if libc_excl.to_string() == opts.dst_v6.to_string() {
            return Err("BLOCKED_BY_ROUTE_SETUP: dst equals relay exclusion".to_string());
        }
    }
    if !run_ip(&["-6", "route", "add", &dst, "dev", &dev.name])
        .map_err(|e| format!("BLOCKED_BY_ROUTE_SETUP: {e}"))?
    {
        return Err("BLOCKED_BY_ROUTE_SETUP".to_string());
    }
    let _guard = RouteGuard {
        dst: dst.clone(),
        ifname: dev.name.clone(),
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpRouteInstalled,
        "wide tun smoltcp route installed",
        json!({
            "ifname": dev.name,
            "controlled_route": dst,
            "default_route_touched": false,
            "relay_excluded": opts.relay_exclude.map(|x| x.to_string()),
        }),
    );

    // Read packets until one controlled IPv6 packet is observed or timeout.
    let mut buf = vec![0u8; 2048];
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(opts.observe_secs);
    let mut observed = false;
    let mut observed_dst = None;
    // Non-blocking-ish: set a read timeout via the fd.
    while std::time::Instant::now() < deadline && !observed {
        match dev.read_packet(&mut buf) {
            Ok(n) if n > 0 => {
                if let Ok(flow) = decode_tcp(&buf[..n]) {
                    if flow.is_ipv6() {
                        observed = true;
                        observed_dst = Some(flow.dst().to_string());
                        runtime_jsonl::emit(
                            "info",
                            RuntimeEventCode::WideTunSmoltcpIpv6PacketObserved,
                            "wide tun smoltcp ipv6 packet observed",
                            json!({
                                "ifname": dev.name,
                                "dst": flow.dst().to_string(),
                                "dst_port": flow.dst_port(),
                                "opens_flow": flow.opens_flow(),
                                "note": "observed only; no smoltcp/relay in this layer",
                            }),
                        );
                    }
                }
            }
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(_) => break,
        }
    }

    Ok(LabResult {
        device_created: true,
        route_installed: true,
        ipv6_packet_observed: observed,
        observed_dst,
        default_route_touched: false,
    })
    // _guard drops here -> route removed + cleanup event
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_interface_names_are_refused_before_opening_tun() {
        for name in [
            "",
            ".",
            "..",
            "too-long-tun-name",
            "tun%d",
            "tun/0",
            "tun 0",
        ] {
            assert_eq!(
                TunDevice::open(name).err().unwrap().kind(),
                io::ErrorKind::InvalidInput
            );
        }
    }

    #[test]
    fn lab_opts_defaults_are_controlled() {
        let o = LabOpts::new("2606:4700:4700::1111".parse().unwrap());
        assert_eq!(o.ifname, "aegis-tun0");
        assert!(o.relay_exclude.is_none());
        assert!(o.observe_secs > 0);
    }

    #[test]
    fn tunsetiff_constant_is_pinned() {
        // Guards against an accidental edit of the ioctl request value.
        assert_eq!(TUNSETIFF, 0x4004_54ca);
        assert_eq!((IFF_TUN | IFF_NO_PI) as u16, 0x1001);
    }
}
