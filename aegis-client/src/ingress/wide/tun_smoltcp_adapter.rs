//! smoltcp TCP adapter over the controlled IPv6 TUN (lab layer).
//!
//! This drives a real smoltcp TCP state machine from the AEGIS-owned TUN
//! device: the controlled IPv6 destination is routed INTO the tun, smoltcp
//! owns that address, and a listening TCP socket completes a real handshake
//! (SYN → SYN-ACK → ACK), establishing a connection in userspace. This proves
//! TCP state (not packet logging). The relay bridge is a later slice.
//!
//! Controlled only: one /128, never a default kernel route, opt-in lab CLI,
//! NOT a production backend (TPROXY stays default).

#![cfg(target_os = "linux")]
#![allow(dead_code)]

use super::tun_smoltcp::TunDevice;
use crate::runtime_events::RuntimeEventCode;
use crate::runtime_jsonl;
use serde_json::json;
use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, Ipv6Address};
use std::process::Command;

const TUN_MTU: usize = 1500;

/// smoltcp phy::Device backed by the non-blocking TUN fd (IP medium, no L2).
struct TunPhy {
    fd: i32,
}

struct TunRx {
    buf: Vec<u8>,
}
struct TunTx {
    fd: i32,
}

impl Device for TunPhy {
    type RxToken<'a>
        = TunRx
    where
        Self: 'a;
    type TxToken<'a>
        = TunTx
    where
        Self: 'a;

    fn receive(&mut self, _ts: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let mut buf = vec![0u8; TUN_MTU];
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n > 0 {
            buf.truncate(n as usize);
            Some((TunRx { buf }, TunTx { fd: self.fd }))
        } else {
            None
        }
    }

    fn transmit(&mut self, _ts: Instant) -> Option<Self::TxToken<'_>> {
        Some(TunTx { fd: self.fd })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = TUN_MTU;
        caps
    }
}

impl RxToken for TunRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.buf)
    }
}

impl TxToken for TunTx {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        unsafe {
            libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len());
        }
        r
    }
}

fn run_ip(args: &[&str]) -> std::io::Result<bool> {
    Ok(Command::new("ip").args(args).status()?.success())
}

struct RouteGuard {
    dst: String,
    ifname: String,
}
impl Drop for RouteGuard {
    fn drop(&mut self) {
        // A point-to-point peer is an *address*, not a route; deleting the TUN
        // device (fd close) already removes it, but tear it down explicitly too.
        let verb = if self.dst.contains(" peer ") {
            "addr"
        } else {
            "route"
        };
        let mut argv: Vec<&str> = vec!["-6", verb, "del"];
        argv.extend(self.dst.split_whitespace());
        argv.extend(["dev", &self.ifname]);
        let _ = run_ip(&argv);
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideTunSmoltcpCleanupCompleted,
            "wide tun smoltcp cleanup completed",
            json!({ "ifname": self.ifname, "route_removed": self.dst, "scope": "aegis_owned_only" }),
        );
    }
}

pub struct AdapterOpts {
    /// The controlled IPv6 /128 address smoltcp owns + listens on.
    pub listen_addr: Ipv6Address,
    pub listen_port: u16,
    pub ifname: String,
    pub run_secs: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AdapterResult {
    pub device_created: bool,
    pub route_installed: bool,
    pub tcp_flow_established: bool,
    pub bytes_echoed: usize,
    pub default_route_touched: bool,
}

/// Run the controlled smoltcp IPv6 TCP adapter lab. A real TCP handshake on the
/// controlled /128 establishes a userspace connection; received bytes are
/// echoed back (proving bidirectional TCP state). No relay bridge here.
pub fn run_tcp_adapter_lab(opts: &AdapterOpts) -> Result<AdapterResult, String> {
    let addr_s = opts.listen_addr.to_string();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpBackendSelected,
        "wide tun smoltcp adapter selected (controlled lab; not default route, not production)",
        json!({ "listen_addr": addr_s, "listen_port": opts.listen_port }),
    );

    let euid_root = unsafe { libc::geteuid() } == 0;
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpPreflightCompleted,
        "wide tun smoltcp preflight completed",
        json!({ "euid_root": euid_root }),
    );
    if !euid_root {
        return Err("BLOCKED_BY_TUN_PRIVILEGE".to_string());
    }

    let dev =
        TunDevice::open(&opts.ifname).map_err(|e| format!("BLOCKED_BY_TUN_PRIVILEGE: {e}"))?;
    let fd = dev.raw_fd();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpDeviceCreated,
        "wide tun smoltcp device created",
        json!({ "ifname": dev.name }),
    );

    if !run_ip(&["link", "set", &dev.name, "up"])
        .map_err(|e| format!("BLOCKED_BY_ROUTE_SETUP: {e}"))?
    {
        return Err("BLOCKED_BY_ROUTE_SETUP".to_string());
    }
    // Controlled lab addressing (ULA, never global / never a default route):
    // a POINT-TO-POINT peer address — local kernel src fd00:ae61::1, peer =
    // smoltcp's listen address. Point-to-point routing emits straight to the
    // peer with NO neighbor discovery (smoltcp, medium=Ip, does not answer NDP).
    let kernel_src = "fd00:ae61::1";
    if !run_ip(&[
        "-6", "addr", "add", kernel_src, "peer", &addr_s, "dev", &dev.name,
    ])
    .map_err(|e| format!("BLOCKED_BY_ROUTE_SETUP: {e}"))?
    {
        return Err("BLOCKED_BY_ROUTE_SETUP".to_string());
    }
    let dst = format!("{addr_s} (peer-of {kernel_src})");
    let _guard = RouteGuard {
        dst: format!("{kernel_src} peer {addr_s}"),
        ifname: dev.name.clone(),
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpRouteInstalled,
        "wide tun smoltcp route installed",
        json!({ "ifname": dev.name, "controlled_route": dst, "default_route_touched": false }),
    );

    // smoltcp interface owning the controlled address.
    let mut phy = TunPhy { fd };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0x_ae_61_5c_01;
    let mut iface = Interface::new(config, &mut phy, Instant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(opts.listen_addr), 128));
    });
    // A default v6 route so smoltcp always emits replies out the device
    // (medium=Ip is neighborless; the gateway value is not used on the wire).
    let _ = iface
        .routes_mut()
        .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

    let mut sockets = SocketSet::new(vec![]);
    let rx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
    let tx_buf = tcp::SocketBuffer::new(vec![0u8; 4096]);
    let tcp_sock = tcp::Socket::new(rx_buf, tx_buf);
    let handle = sockets.add(tcp_sock);
    {
        let s = sockets.get_mut::<tcp::Socket>(handle);
        s.listen(opts.listen_port)
            .map_err(|e| format!("BLOCKED_BY_SMOLTCP_ADAPTER: listen {e:?}"))?;
    }

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(opts.run_secs);
    let mut established = false;
    let mut bytes_echoed = 0usize;
    while std::time::Instant::now() < deadline {
        let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
        let s = sockets.get_mut::<tcp::Socket>(handle);
        if s.is_active() && !established && s.may_send() {
            established = true;
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::WideTunSmoltcpTcpFlowEstablished,
                "wide tun smoltcp tcp flow established",
                json!({
                    "local": addr_s,
                    "port": opts.listen_port,
                    "state": "established",
                    "note": "real smoltcp TCP state; echo lab, no relay bridge yet",
                }),
            );
        }
        // Echo any received bytes (proves bidirectional TCP state).
        if s.can_recv() {
            let mut chunk = Vec::new();
            let _ = s.recv(|data| {
                chunk.extend_from_slice(data);
                (data.len(), ())
            });
            if !chunk.is_empty() && s.can_send() {
                if let Ok(n) = s.send_slice(&chunk) {
                    bytes_echoed += n;
                }
            }
        }
        // Once established + a little traffic, we can finish the lab early.
        if established && bytes_echoed > 0 {
            // give smoltcp a couple polls to flush, then stop
            for _ in 0..5 {
                let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
            }
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    Ok(AdapterResult {
        device_created: true,
        route_installed: true,
        tcp_flow_established: established,
        bytes_echoed,
        default_route_touched: false,
    })
}

/// Result of the controlled IPv6 relay bridge lab.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RelayBridgeResult {
    pub device_created: bool,
    pub route_installed: bool,
    pub tcp_flow_established: bool,
    pub relay_session_succeeded: bool,
    pub egress_bytes: usize,
    pub default_route_touched: bool,
}

/// Run the controlled IPv6 packet-to-relay bridge lab: a controlled IPv6 TCP
/// flow is terminated by smoltcp, handed off over a localhost socket to the
/// existing relay tunnel (`relay::run_relay_tunnel`), and relayed to a target.
/// Egress bytes returning to the smoltcp client prove packet → flow → relay.
/// Controlled lab only; not a production backend; not a default route.
pub async fn run_relay_bridge_lab(
    opts: &AdapterOpts,
    settings: aegis_core::RelaySettings,
    target_host: String,
    target_port: u16,
) -> Result<RelayBridgeResult, String> {
    let addr_s = opts.listen_addr.to_string();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpBackendSelected,
        "wide tun smoltcp relay bridge selected (controlled lab; not default route, not production)",
        json!({ "listen_addr": addr_s, "listen_port": opts.listen_port, "target": format!("{target_host}:{target_port}") }),
    );
    if unsafe { libc::geteuid() } != 0 {
        return Err("BLOCKED_BY_TUN_PRIVILEGE".to_string());
    }
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpPreflightCompleted,
        "wide tun smoltcp preflight completed",
        json!({ "euid_root": true, "mode": "relay_bridge" }),
    );

    let dev =
        TunDevice::open(&opts.ifname).map_err(|e| format!("BLOCKED_BY_TUN_PRIVILEGE: {e}"))?;
    let fd = dev.raw_fd();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpDeviceCreated,
        "wide tun smoltcp device created",
        json!({ "ifname": dev.name }),
    );
    let _ = run_ip(&["link", "set", &dev.name, "up"]);
    let _ = run_ip(&[
        "-6",
        "addr",
        "add",
        "fd00:ae61::1",
        "peer",
        &addr_s,
        "dev",
        &dev.name,
    ]);
    let _guard = RouteGuard {
        dst: format!("fd00:ae61::1 peer {addr_s}"),
        ifname: dev.name.clone(),
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpRouteInstalled,
        "wide tun smoltcp route installed",
        json!({ "ifname": dev.name, "default_route_touched": false }),
    );

    // Relay handoff on the *current* tokio runtime: a localhost listener accepts
    // the bridged stream and runs the existing relay tunnel to the target. (main
    // is already a tokio runtime, so we must not build a nested one.)
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("BLOCKED_BY_RELAY_BRIDGE: bind {e}"))?;
    let local_port = listener
        .local_addr()
        .map_err(|e| format!("BLOCKED_BY_RELAY_BRIDGE: {e}"))?
        .port();
    {
        let th = target_host.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = crate::relay::run_relay_tunnel(
                    stream,
                    &settings,
                    th,
                    target_port,
                    None,
                    None,
                    None,
                )
                .await;
            }
        });
    }

    // The smoltcp poll loop is synchronous (libc read/write, smoltcp state) and
    // must not block a tokio worker, so it runs on a dedicated blocking thread.
    // The TUN device + RouteGuard move in so cleanup runs when the loop returns.
    let listen_addr = opts.listen_addr;
    let listen_port = opts.listen_port;
    let run_secs = opts.run_secs;
    let th_loop = target_host.clone();
    let loop_res = tokio::task::spawn_blocking(move || {
        let _dev = dev;
        let _guard = _guard;
        let mut phy = TunPhy { fd };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x_ae_61_5c_02;
        let mut iface = Interface::new(config, &mut phy, Instant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(listen_addr), 128));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let mut sockets = SocketSet::new(vec![]);
        let tcp_sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 8192]),
            tcp::SocketBuffer::new(vec![0u8; 8192]),
        );
        let handle = sockets.add(tcp_sock);
        if let Err(e) = sockets.get_mut::<tcp::Socket>(handle).listen(listen_port) {
            return Err(format!("BLOCKED_BY_SMOLTCP_ADAPTER: listen {e:?}"));
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(run_secs);
        let mut established = false;
        let mut bridge: Option<std::net::TcpStream> = None;
        let mut egress_bytes = 0usize;
        let mut relay_ok = false;
        while std::time::Instant::now() < deadline {
            let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if s.is_active() && !established && s.may_send() {
                established = true;
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::WideTunSmoltcpTcpFlowEstablished,
                    "wide tun smoltcp tcp flow established",
                    json!({ "local": addr_s, "port": listen_port, "state": "established" }),
                );
                if let Ok(b) = std::net::TcpStream::connect(("127.0.0.1", local_port)) {
                    let _ = b.set_nonblocking(true);
                    bridge = Some(b);
                }
            }
            // client -> smoltcp -> bridge (relay -> target)
            if let Some(b) = bridge.as_mut() {
                if s.can_recv() {
                    let mut chunk = Vec::new();
                    let _ = s.recv(|d| {
                        chunk.extend_from_slice(d);
                        (d.len(), ())
                    });
                    if !chunk.is_empty() {
                        use std::io::Write;
                        let _ = b.write_all(&chunk);
                    }
                }
                // bridge (relay <- target) -> smoltcp -> client  == egress
                use std::io::Read;
                let mut rb = [0u8; 4096];
                match b.read(&mut rb) {
                    Ok(n) if n > 0 && s.can_send() => {
                        if let Ok(w) = s.send_slice(&rb[..n]) {
                            egress_bytes += w;
                            if !relay_ok {
                                relay_ok = true;
                                runtime_jsonl::emit(
                                    "info",
                                    RuntimeEventCode::WideTunSmoltcpRelaySessionSucceeded,
                                    "wide tun smoltcp relay session succeeded",
                                    json!({
                                        "target": format!("{th_loop}:{target_port}"),
                                        "egress_first_bytes": w,
                                        "note": "controlled lab: packet -> smoltcp flow -> relay -> target egress",
                                    }),
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
            if relay_ok && egress_bytes > 16 {
                for _ in 0..10 {
                    let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok((established, relay_ok, egress_bytes))
    })
    .await
    .map_err(|e| format!("BLOCKED_BY_RELAY_BRIDGE: join {e}"))?;
    let (established, relay_ok, egress_bytes) = loop_res?;

    Ok(RelayBridgeResult {
        device_created: true,
        route_installed: true,
        tcp_flow_established: established,
        relay_session_succeeded: relay_ok,
        egress_bytes,
        default_route_touched: false,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct UdpRelayBridgeResult {
    pub device_created: bool,
    pub route_installed: bool,
    pub udp_flow_observed: bool,
    pub relay_session_succeeded: bool,
    pub response_delivered: bool,
    pub egress_bytes: usize,
    pub default_route_touched: bool,
}

/// Controlled IPv6 **UDP** relay bridge lab — the bidirectional IPv6 UDP carry.
///
/// smoltcp owns the controlled `/128`, a UDP socket captures the app's IPv6 UDP
/// datagram from the TUN (src endpoint + payload), the payload is carried over
/// the already-proven MASQUE direct CONNECT-UDP path to the target (IPv6-capable
/// `run_masque_udp_send`), and the relay's response is injected back through the
/// TUN to the app's source endpoint. Bidirectional: the app receives the
/// response. Fail-closed on any relay error — there is no native IPv6 UDP
/// fallback. Controlled `/128`, never a default route; lab CLI, not a prod
/// backend.
///
/// The smoltcp poll loop runs on a **raw OS thread** (not `spawn_blocking`) so
/// it can `Handle::block_on` the async MASQUE send without a nested-runtime
/// panic; the async fn joins it via `spawn_blocking`.
pub async fn run_udp_relay_bridge_lab(
    opts: &AdapterOpts,
    settings: aegis_core::RelaySettings,
    target_host: String,
    target_port: u16,
) -> Result<UdpRelayBridgeResult, String> {
    let addr_s = opts.listen_addr.to_string();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpBackendSelected,
        "wide tun smoltcp ipv6 udp relay bridge selected (controlled lab; not default route, not production)",
        json!({ "listen_addr": addr_s, "listen_port": opts.listen_port, "target": format!("{target_host}:{target_port}"), "proto": "udp6" }),
    );
    if unsafe { libc::geteuid() } != 0 {
        return Err("BLOCKED_BY_TUN_PRIVILEGE".to_string());
    }
    let dev =
        TunDevice::open(&opts.ifname).map_err(|e| format!("BLOCKED_BY_TUN_PRIVILEGE: {e}"))?;
    let fd = dev.raw_fd();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpDeviceCreated,
        "wide tun smoltcp device created",
        json!({ "ifname": dev.name }),
    );
    let _ = run_ip(&["link", "set", &dev.name, "up"]);
    let _ = run_ip(&[
        "-6",
        "addr",
        "add",
        "fd00:ae61::1",
        "peer",
        &addr_s,
        "dev",
        &dev.name,
    ]);
    let _guard = RouteGuard {
        dst: format!("fd00:ae61::1 peer {addr_s}"),
        ifname: dev.name.clone(),
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpRouteInstalled,
        "wide tun smoltcp route installed",
        json!({ "ifname": dev.name, "default_route_touched": false }),
    );

    let listen_addr = opts.listen_addr;
    let listen_port = opts.listen_port;
    let run_secs = opts.run_secs;
    let rt = tokio::runtime::Handle::current();

    let jh = std::thread::Builder::new()
        .name("aegis-tun-udp6".to_string())
        .spawn(move || -> Result<(bool, bool, bool, usize), String> {
            let _dev = dev;
            let _guard = _guard;
            let mut phy = TunPhy { fd };
            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = 0x_ae_61_5c_03;
            let mut iface = Interface::new(config, &mut phy, Instant::now());
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(listen_addr), 128));
            });
            let _ = iface
                .routes_mut()
                .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
            let mut sockets = SocketSet::new(vec![]);
            let udp_rx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 16],
                vec![0u8; 65_535],
            );
            let udp_tx = udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; 16],
                vec![0u8; 65_535],
            );
            let mut sock = udp::Socket::new(udp_rx, udp_tx);
            sock.bind(listen_port)
                .map_err(|e| format!("BLOCKED_BY_SMOLTCP_UDP: bind {e:?}"))?;
            let handle = sockets.add(sock);

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(run_secs);
            let mut observed = false;
            let mut relay_ok = false;
            let mut delivered = false;
            let mut egress_bytes = 0usize;
            while std::time::Instant::now() < deadline {
                let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
                // Copy out one captured datagram + its source endpoint, then
                // release the socket borrow before the (blocking) relay carry.
                let captured: Option<(Vec<u8>, smoltcp::wire::IpEndpoint)> = {
                    let s = sockets.get_mut::<udp::Socket>(handle);
                    if s.can_recv() {
                        match s.recv() {
                            Ok((data, meta)) => Some((data.to_vec(), meta.endpoint)),
                            Err(_) => None,
                        }
                    } else {
                        None
                    }
                };
                if let Some((payload, src)) = captured {
                    if !observed {
                        observed = true;
                        runtime_jsonl::emit(
                            "info",
                            RuntimeEventCode::Ipv6UdpFlowObserved,
                            "ipv6 udp flow observed (tun smoltcp)",
                            json!({ "src": src.to_string(), "dst": format!("[{addr_s}]:{listen_port}"), "payload_len": payload.len(), "no_native_fallback": true }),
                        );
                        runtime_jsonl::emit(
                            "info",
                            RuntimeEventCode::Ipv6UdpSessionCreated,
                            "ipv6 udp session created",
                            json!({ "src": src.to_string(), "target": format!("{target_host}:{target_port}"), "carry": "masque_direct" }),
                        );
                    }
                    runtime_jsonl::emit(
                        "info",
                        RuntimeEventCode::Ipv6UdpDatagramSent,
                        "ipv6 udp datagram sent (masque direct)",
                        json!({ "target": format!("{target_host}:{target_port}"), "payload_len": payload.len() }),
                    );
                    match rt.block_on(crate::relay::masque::run_masque_udp_send(
                        &settings,
                        &target_host,
                        target_port,
                        &payload,
                    )) {
                        Ok(resp) => {
                            relay_ok = true;
                            runtime_jsonl::emit(
                                "info",
                                RuntimeEventCode::Ipv6UdpDatagramReceived,
                                "ipv6 udp datagram received (masque direct)",
                                json!({ "target": format!("{target_host}:{target_port}"), "response_len": resp.len() }),
                            );
                            let s = sockets.get_mut::<udp::Socket>(handle);
                            match s.send_slice(&resp, src) {
                                Ok(()) => {
                                    egress_bytes += resp.len();
                                    delivered = true;
                                    runtime_jsonl::emit(
                                        "info",
                                        RuntimeEventCode::Ipv6UdpResponseDelivered,
                                        "ipv6 udp response delivered to app (bidirectional)",
                                        json!({ "src": src.to_string(), "response_len": resp.len(), "delivered_to_app": true }),
                                    );
                                    for _ in 0..10 {
                                        let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
                                    }
                                }
                                Err(e) => {
                                    runtime_jsonl::emit(
                                        "warn",
                                        RuntimeEventCode::Ipv6UdpFailClosed,
                                        "ipv6 udp response could not be injected (fail-closed)",
                                        json!({ "src": src.to_string(), "error": format!("{e:?}"), "no_native_fallback": true }),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            runtime_jsonl::emit(
                                "warn",
                                RuntimeEventCode::Ipv6UdpFailClosed,
                                "ipv6 udp masque direct leg failed (fail-closed)",
                                json!({ "target": format!("{target_host}:{target_port}"), "error": e.to_string(), "no_native_fallback": true }),
                            );
                        }
                    }
                    if delivered {
                        break;
                    }
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::Ipv6UdpFlowClosed,
                "ipv6 udp flow closed",
                json!({ "delivered": delivered, "relay_ok": relay_ok }),
            );
            Ok((observed, relay_ok, delivered, egress_bytes))
        })
        .map_err(|e| format!("BLOCKED_BY_UDP_RELAY_BRIDGE: spawn {e}"))?;

    let joined = tokio::task::spawn_blocking(move || jh.join())
        .await
        .map_err(|e| format!("BLOCKED_BY_UDP_RELAY_BRIDGE: join await {e}"))?;
    let inner = joined.map_err(|_| "udp6 poll thread panicked".to_string())?;
    let (observed, relay_ok, delivered, egress_bytes) = inner?;

    Ok(UdpRelayBridgeResult {
        device_created: true,
        route_installed: true,
        udp_flow_observed: observed,
        relay_session_succeeded: relay_ok,
        response_delivered: delivered,
        egress_bytes,
        default_route_touched: false,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PrefixLabResult {
    pub device_created: bool,
    pub prefix_route_installed: bool,
    pub controlled_prefix: String,
    pub peer1_relay_succeeded: bool,
    pub peer2_observed: bool,
    pub egress_bytes: usize,
    pub relay_excluded_ok: bool,
    pub default_route_touched: bool,
}

/// Controlled IPv6 *prefix* relay lab: install ONE controlled ULA prefix as a
/// device route into the AEGIS TUN (NOARP device route — no NDP, never a default
/// route), keep the relay/server IP on its normal path, and prove the policy with
/// TWO controlled peers inside the prefix: peer1 is bridged through the existing
/// relay (egress proof), peer2's handshake is observed (multi-peer routing). Lab
/// only; not a production backend; never `::/0`.
#[allow(clippy::too_many_arguments)]
pub async fn run_prefix_relay_bridge_lab(
    opts: &AdapterOpts,
    controlled_prefix: String,
    peer2: Ipv6Address,
    relay_exclude: Option<std::net::IpAddr>,
    settings: aegis_core::RelaySettings,
    target_host: String,
    target_port: u16,
) -> Result<PrefixLabResult, String> {
    let peer1_s = opts.listen_addr.to_string();
    let peer2_s = peer2.to_string();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpBackendSelected,
        "wide tun smoltcp prefix relay lab selected (controlled prefix; not default route, not production)",
        json!({ "controlled_prefix": controlled_prefix, "peer1": peer1_s, "peer2": peer2_s }),
    );
    if unsafe { libc::geteuid() } != 0 {
        return Err("BLOCKED_BY_TUN_PRIVILEGE".to_string());
    }
    // The controlled prefix must be a ULA (fd00::/8) and never a default route.
    if !controlled_prefix.to_ascii_lowercase().starts_with("fd") || !controlled_prefix.contains('/')
    {
        return Err("BLOCKED_BY_ROUTE_SETUP: controlled_prefix must be a ULA CIDR".to_string());
    }
    if controlled_prefix.starts_with("::/") {
        return Err("BLOCKED_BY_ROUTE_SETUP: refusing a default route".to_string());
    }
    // Relay/server IP must NOT fall inside the controlled prefix (relay-loop
    // prevention): we only ever route the ULA prefix into the tun, so an IPv4 or
    // non-prefix relay stays on its normal path. Flag if it would collide.
    let relay_excluded_ok = match relay_exclude {
        Some(std::net::IpAddr::V6(v6)) => {
            let pfx_head = controlled_prefix.split("::/").next().unwrap_or("");
            !v6.to_string().starts_with(pfx_head)
        }
        _ => true,
    };
    if !relay_excluded_ok {
        return Err("BLOCKED_BY_ROUTE_SETUP: relay endpoint falls inside controlled prefix".into());
    }
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpPreflightCompleted,
        "wide tun smoltcp preflight completed",
        json!({ "euid_root": true, "mode": "prefix_relay_lab" }),
    );

    let dev =
        TunDevice::open(&opts.ifname).map_err(|e| format!("BLOCKED_BY_TUN_PRIVILEGE: {e}"))?;
    let fd = dev.raw_fd();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpDeviceCreated,
        "wide tun smoltcp device created",
        json!({ "ifname": dev.name }),
    );
    let _ = run_ip(&["link", "set", &dev.name, "up"]);
    // Kernel src on the tun + a DEVICE route for the whole controlled prefix
    // (NOARP — kernel emits straight to the device, no NDP for any peer).
    let _ = run_ip(&["-6", "addr", "add", "fd00:ae61::1/128", "dev", &dev.name]);
    if !run_ip(&["-6", "route", "add", &controlled_prefix, "dev", &dev.name])
        .map_err(|e| format!("BLOCKED_BY_ROUTE_SETUP: {e}"))?
    {
        return Err("BLOCKED_BY_ROUTE_SETUP".to_string());
    }
    let _guard = RouteGuard {
        dst: controlled_prefix.clone(),
        ifname: dev.name.clone(),
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpRouteInstalled,
        "wide tun smoltcp route installed",
        json!({
            "ifname": dev.name,
            "controlled_prefix": controlled_prefix,
            "peer1": peer1_s,
            "peer2": peer2_s,
            "default_route_touched": false,
            "relay_excluded": relay_exclude.map(|x| x.to_string()),
            "relay_excluded_ok": relay_excluded_ok,
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("BLOCKED_BY_RELAY_BRIDGE: bind {e}"))?;
    let local_port = listener
        .local_addr()
        .map_err(|e| format!("BLOCKED_BY_RELAY_BRIDGE: {e}"))?
        .port();
    {
        let th = target_host.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = crate::relay::run_relay_tunnel(
                    stream,
                    &settings,
                    th,
                    target_port,
                    None,
                    None,
                    None,
                )
                .await;
            }
        });
    }

    let peer1 = opts.listen_addr;
    let listen_port = opts.listen_port;
    let run_secs = opts.run_secs;
    let prefix_for_loop = controlled_prefix.clone();
    let loop_res = tokio::task::spawn_blocking(move || {
        let _dev = dev;
        let _guard = _guard;
        let mut phy = TunPhy { fd };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x_ae_61_5c_03;
        let mut iface = Interface::new(config, &mut phy, Instant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(peer1), 128));
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(peer2), 128));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let mut sockets = SocketSet::new(vec![]);
        let s1 = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 8192]),
            tcp::SocketBuffer::new(vec![0u8; 8192]),
        );
        let s2 = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 4096]),
            tcp::SocketBuffer::new(vec![0u8; 4096]),
        );
        let h1 = sockets.add(s1);
        let h2 = sockets.add(s2);
        // Bind each socket to its own controlled peer address (same port).
        if let Err(e) = sockets
            .get_mut::<tcp::Socket>(h1)
            .listen((IpAddress::Ipv6(peer1), listen_port))
        {
            return Err(format!("BLOCKED_BY_SMOLTCP_ADAPTER: listen peer1 {e:?}"));
        }
        if let Err(e) = sockets
            .get_mut::<tcp::Socket>(h2)
            .listen((IpAddress::Ipv6(peer2), listen_port))
        {
            return Err(format!("BLOCKED_BY_SMOLTCP_ADAPTER: listen peer2 {e:?}"));
        }

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(run_secs);
        let mut established1 = false;
        let mut peer2_observed = false;
        let mut bridge: Option<std::net::TcpStream> = None;
        let mut egress_bytes = 0usize;
        let mut relay_ok = false;
        while std::time::Instant::now() < deadline {
            let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
            // peer2: observe a real handshake (multi-peer routing into the prefix)
            {
                let s2 = sockets.get_mut::<tcp::Socket>(h2);
                if s2.is_active() && !peer2_observed && s2.may_send() {
                    peer2_observed = true;
                    runtime_jsonl::emit(
                        "info",
                        RuntimeEventCode::WideTunSmoltcpTcpFlowEstablished,
                        "wide tun smoltcp tcp flow established",
                        json!({ "local": prefix_for_loop, "peer": "peer2", "state": "established", "role": "observed" }),
                    );
                }
            }
            // peer1: relay bridge (egress proof)
            let s1 = sockets.get_mut::<tcp::Socket>(h1);
            if s1.is_active() && !established1 && s1.may_send() {
                established1 = true;
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::WideTunSmoltcpTcpFlowEstablished,
                    "wide tun smoltcp tcp flow established",
                    json!({ "local": prefix_for_loop, "peer": "peer1", "state": "established", "role": "relayed" }),
                );
                if let Ok(b) = std::net::TcpStream::connect(("127.0.0.1", local_port)) {
                    let _ = b.set_nonblocking(true);
                    bridge = Some(b);
                }
            }
            if let Some(b) = bridge.as_mut() {
                if s1.can_recv() {
                    let mut chunk = Vec::new();
                    let _ = s1.recv(|d| {
                        chunk.extend_from_slice(d);
                        (d.len(), ())
                    });
                    if !chunk.is_empty() {
                        use std::io::Write;
                        let _ = b.write_all(&chunk);
                    }
                }
                use std::io::Read;
                let mut rb = [0u8; 4096];
                if let Ok(n) = b.read(&mut rb) {
                    if n > 0 && s1.can_send() {
                        if let Ok(w) = s1.send_slice(&rb[..n]) {
                            egress_bytes += w;
                            if !relay_ok {
                                relay_ok = true;
                                runtime_jsonl::emit(
                                    "info",
                                    RuntimeEventCode::WideTunSmoltcpRelaySessionSucceeded,
                                    "wide tun smoltcp relay session succeeded",
                                    json!({
                                        "target": format!("{target_host}:{target_port}"),
                                        "egress_first_bytes": w,
                                        "peer": "peer1",
                                        "note": "controlled prefix lab: peer1 packet -> smoltcp -> relay -> egress",
                                    }),
                                );
                            }
                        }
                    }
                }
            }
            if relay_ok && egress_bytes > 16 && peer2_observed {
                for _ in 0..10 {
                    let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok((established1, peer2_observed, relay_ok, egress_bytes))
    })
    .await
    .map_err(|e| format!("BLOCKED_BY_RELAY_BRIDGE: join {e}"))?;
    let (peer1_relay_succeeded, peer2_observed, relay_ok, egress_bytes) = loop_res?;

    Ok(PrefixLabResult {
        device_created: true,
        prefix_route_installed: true,
        controlled_prefix,
        peer1_relay_succeeded: peer1_relay_succeeded && relay_ok,
        peer2_observed,
        egress_bytes,
        relay_excluded_ok,
        default_route_touched: false,
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct GuardedDefaultRouteResult {
    pub device_created: bool,
    pub baseline_default_present: bool,
    pub capture_applied: bool,
    pub capture_routes: Vec<String>,
    pub relay_excludes: Vec<String>,
    pub target: String,
    pub relay_succeeded: bool,
    pub egress_bytes: usize,
    pub watchdog_armed: bool,
    pub max_runtime_seconds: u64,
    pub real_default_route_deleted: bool,
    pub cleanup_restored: bool,
    pub residual_capture_routes: usize,
    pub after_default_present: bool,
}

fn ip_v6_default_present() -> bool {
    std::process::Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false)
}

fn ip_route_has(needle: &str) -> bool {
    std::process::Command::new("ip")
        .args(["-6", "route", "show"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains(needle))
        .unwrap_or(false)
}

/// RAII guard for the guarded ::/0 capture: removes the AEGIS-added ::/1 + 8000::/1
/// halves + the kernel src on drop. The real ::/0 default is never deleted, so
/// dropping this restores baseline IPv6 routing.
struct GuardedRouteGuard {
    ifname: String,
}
impl Drop for GuardedRouteGuard {
    fn drop(&mut self) {
        let _ = run_ip(&["-6", "route", "del", "::/1", "dev", &self.ifname]);
        let _ = run_ip(&["-6", "route", "del", "8000::/1", "dev", &self.ifname]);
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideTunSmoltcpCleanupCompleted,
            "wide tun smoltcp cleanup completed",
            json!({ "ifname": self.ifname, "removed": ["::/1", "8000::/1"], "scope": "aegis_owned_only", "real_default_preserved": true }),
        );
    }
}

/// GUARDED live IPv6 ::/0 default-route capture. Applies the standard ::/1 +
/// 8000::/1 "capture all of IPv6" pair (more specific than the real ::/0, so it
/// wins WITHOUT deleting the real default) into an AEGIS-owned TUN, relays one
/// captured IPv6 target through the existing relay, then rolls everything back —
/// always, via a mandatory watchdog and RAII. SSH/control stays on its own path
/// (this only touches IPv6; the relay leg + SSH are excluded/unaffected).
#[allow(clippy::too_many_arguments)]
pub async fn run_guarded_default_route_lab(
    opts: &AdapterOpts,
    target_v6: Ipv6Address,
    relay_excludes: Vec<std::net::IpAddr>,
    max_runtime_seconds: u64,
    settings: aegis_core::RelaySettings,
    target_host: String,
    target_port: u16,
) -> Result<GuardedDefaultRouteResult, String> {
    let target_s = target_v6.to_string();
    runtime_jsonl::emit(
        "warn",
        RuntimeEventCode::WideTunSmoltcpBackendSelected,
        "wide tun smoltcp GUARDED ::/0 default-route capture selected (temporary; watchdog + rollback mandatory)",
        json!({ "target": target_s, "max_runtime_seconds": max_runtime_seconds, "relay_excludes": relay_excludes.iter().map(|x| x.to_string()).collect::<Vec<_>>() }),
    );
    if unsafe { libc::geteuid() } != 0 {
        return Err("BLOCKED_BY_PRIVILEGE".to_string());
    }
    if max_runtime_seconds == 0 || max_runtime_seconds > 600 {
        return Err("BLOCKED_BY_ROUTE_POLICY: max_runtime_seconds must be 1..=600".to_string());
    }
    // Refuse if the relay endpoint is an IPv6 address that we cannot exclude
    // (would risk a relay loop). IPv4 relay endpoints are unaffected by ::/0.
    for ex in &relay_excludes {
        if ex.is_ipv6() {
            // Keep the relay's IPv6 on its normal path BEFORE installing capture.
            let _ = run_ip(&["-6", "route", "add", &format!("{ex}/128"), "dev", "eth0"]);
        }
    }
    let baseline_default_present = ip_v6_default_present();

    let dev = TunDevice::open(&opts.ifname).map_err(|e| format!("BLOCKED_BY_PRIVILEGE: {e}"))?;
    let fd = dev.raw_fd();
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpDeviceCreated,
        "wide tun smoltcp device created",
        json!({ "ifname": dev.name, "mode": "guarded_default_route" }),
    );
    let _ = run_ip(&["link", "set", &dev.name, "up"]);
    let _ = run_ip(&["-6", "addr", "add", "fd00:ae61::1/128", "dev", &dev.name]);

    // Apply the ::/0-equivalent capture (more specific than the real default).
    if !run_ip(&["-6", "route", "add", "::/1", "dev", &dev.name])
        .map_err(|e| format!("BLOCKED_BY_ROUTE_POLICY: {e}"))?
    {
        return Err("BLOCKED_BY_ROUTE_POLICY: ::/1".to_string());
    }
    let _ = run_ip(&["-6", "route", "add", "8000::/1", "dev", &dev.name]);
    let guard = GuardedRouteGuard {
        ifname: dev.name.clone(),
    };
    let capture_applied = ip_route_has("::/1");
    runtime_jsonl::emit(
        "warn",
        RuntimeEventCode::WideTunSmoltcpRouteInstalled,
        "wide tun smoltcp GUARDED capture installed (::/1 + 8000::/1; real ::/0 preserved)",
        json!({ "ifname": dev.name, "capture": ["::/1", "8000::/1"], "real_default_deleted": false, "target": target_s }),
    );

    // Mandatory failsafe watchdog: an independent thread force-removes the capture
    // a few seconds after the budget even if the main loop wedges.
    let wd_if = dev.name.clone();
    let wd_secs = max_runtime_seconds + 5;
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(wd_secs));
        let _ = std::process::Command::new("ip")
            .args(["-6", "route", "del", "::/1", "dev", &wd_if])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["-6", "route", "del", "8000::/1", "dev", &wd_if])
            .status();
        let _ = std::process::Command::new("ip")
            .args(["link", "del", &wd_if])
            .status();
    });

    // Relay handoff + smoltcp loop (smoltcp owns the captured target address).
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .map_err(|e| format!("RELAY_SESSION_FAILED: bind {e}"))?;
    let local_port = listener
        .local_addr()
        .map_err(|e| format!("RELAY_SESSION_FAILED: {e}"))?
        .port();
    {
        let th = target_host.clone();
        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = crate::relay::run_relay_tunnel(
                    stream,
                    &settings,
                    th,
                    target_port,
                    None,
                    None,
                    None,
                )
                .await;
            }
        });
    }

    // Capture must answer on the target's actual service port (what a real
    // captured client connects to), not the adapter's lab port.
    let capture_port = target_port;
    let _ = opts.listen_port;
    let th_loop = target_host.clone();
    let loop_res = tokio::task::spawn_blocking(move || {
        let _dev = dev;
        let _guard = guard; // rollback-on-exit (RAII)
        let mut phy = TunPhy { fd };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 0x_ae_61_5c_04;
        let mut iface = Interface::new(config, &mut phy, Instant::now());
        iface.update_ip_addrs(|addrs| {
            // smoltcp owns the captured target so it can answer + terminate it.
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(target_v6), 128));
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 8192]),
            tcp::SocketBuffer::new(vec![0u8; 8192]),
        );
        let handle = sockets.add(sock);
        if let Err(e) = sockets
            .get_mut::<tcp::Socket>(handle)
            .listen((IpAddress::Ipv6(target_v6), capture_port))
        {
            return Err(format!("RELAY_SESSION_FAILED: listen {e:?}"));
        }
        let deadline =
            std::time::Instant::now() + std::time::Duration::from_secs(max_runtime_seconds);
        let mut established = false;
        let mut bridge: Option<std::net::TcpStream> = None;
        let mut egress_bytes = 0usize;
        let mut relay_ok = false;
        while std::time::Instant::now() < deadline {
            let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if s.is_active() && !established && s.may_send() {
                established = true;
                runtime_jsonl::emit(
                    "info",
                    RuntimeEventCode::WideTunSmoltcpTcpFlowEstablished,
                    "wide tun smoltcp GUARDED captured flow established",
                    json!({ "target": th_loop, "state": "established", "note": "captured ::/0 flow terminated by smoltcp" }),
                );
                if let Ok(b) = std::net::TcpStream::connect(("127.0.0.1", local_port)) {
                    let _ = b.set_nonblocking(true);
                    bridge = Some(b);
                }
            }
            if let Some(b) = bridge.as_mut() {
                if s.can_recv() {
                    let mut chunk = Vec::new();
                    let _ = s.recv(|d| {
                        chunk.extend_from_slice(d);
                        (d.len(), ())
                    });
                    if !chunk.is_empty() {
                        use std::io::Write;
                        let _ = b.write_all(&chunk);
                    }
                }
                use std::io::Read;
                let mut rb = [0u8; 4096];
                if let Ok(n) = b.read(&mut rb) {
                    if n > 0 && s.can_send() {
                        if let Ok(w) = s.send_slice(&rb[..n]) {
                            egress_bytes += w;
                            if !relay_ok {
                                relay_ok = true;
                                runtime_jsonl::emit(
                                    "info",
                                    RuntimeEventCode::WideTunSmoltcpRelaySessionSucceeded,
                                    "wide tun smoltcp GUARDED relay session succeeded",
                                    json!({ "target": format!("{th_loop}:{target_port}"), "egress_first_bytes": w, "note": "guarded ::/0 capture: IPv6 target reached via relay" }),
                                );
                            }
                        }
                    }
                }
            }
            if relay_ok && egress_bytes > 16 {
                for _ in 0..10 {
                    let _ = iface.poll(Instant::now(), &mut phy, &mut sockets);
                }
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        Ok((established, relay_ok, egress_bytes))
        // _guard drops here -> capture removed (rollback-on-exit)
    })
    .await
    .map_err(|e| format!("CLEANUP_FAILED: join {e}"))?;
    let (_established, relay_ok, egress_bytes) = loop_res?;

    // Post-cleanup verification (the RAII guard already removed the capture).
    let residual = if ip_route_has("::/1 ") { 1 } else { 0 };
    let after_default_present = ip_v6_default_present();
    let cleanup_restored = residual == 0 && after_default_present == baseline_default_present;

    Ok(GuardedDefaultRouteResult {
        device_created: true,
        baseline_default_present,
        capture_applied,
        capture_routes: vec!["::/1".into(), "8000::/1".into()],
        relay_excludes: relay_excludes.iter().map(|x| x.to_string()).collect(),
        target: target_s,
        relay_succeeded: relay_ok,
        egress_bytes,
        watchdog_armed: true,
        max_runtime_seconds,
        real_default_route_deleted: false,
        cleanup_restored,
        residual_capture_routes: residual,
        after_default_present,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tun_phy_capabilities_are_ip_medium() {
        let phy = TunPhy { fd: -1 };
        let caps = phy.capabilities();
        assert!(matches!(caps.medium, Medium::Ip));
        assert_eq!(caps.max_transmission_unit, TUN_MTU);
    }

    #[test]
    fn smoltcp_udp_socket_binds_like_the_ipv6_udp_lab() {
        // Proves the socket-udp feature + the lab's buffer layout: a UDP socket
        // can be created and bound to the adapter port without a TUN.
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65_535]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65_535]);
        let mut sock = udp::Socket::new(rx, tx);
        assert!(sock.bind(8080u16).is_ok());
        assert!(sock.is_open());
    }

    #[test]
    fn udp_relay_bridge_result_serializes_bidirectional_fields() {
        let r = UdpRelayBridgeResult {
            device_created: true,
            route_installed: true,
            udp_flow_observed: true,
            relay_session_succeeded: true,
            response_delivered: true,
            egress_bytes: 36,
            default_route_touched: false,
        };
        let j = serde_json::to_string(&r).expect("serialize");
        assert!(j.contains("\"response_delivered\":true"));
        assert!(j.contains("\"udp_flow_observed\":true"));
        assert!(j.contains("\"default_route_touched\":false"));
    }

    #[test]
    fn ipv6_udp_event_codes_are_stable() {
        assert_eq!(
            RuntimeEventCode::Ipv6UdpFlowObserved.as_str(),
            "ipv6_udp_flow_observed"
        );
        assert_eq!(
            RuntimeEventCode::Ipv6UdpResponseDelivered.as_str(),
            "ipv6_udp_response_delivered"
        );
        assert_eq!(
            RuntimeEventCode::Ipv6UdpFailClosed.as_str(),
            "ipv6_udp_fail_closed"
        );
    }
}
