//! Dual-stack packet engine, reusing the Linux transparent TCP/UDP relay path
//! and its lossless backpressure/half-close pump. OS policy lives outside it.
#[path = "../ingress/wide/ip_tunnel/fragments.rs"]
mod fragments;
use super::dns::{self as dns_preview, lease_target_host, FakeIpMap};
use super::services::{EngineEvent as RuntimeEventCode, RelayServices};
use super::{
    linux_nfqueue::{decode_packet, DecodedPacket},
    tcp_stream_pump::TcpStreamPump,
};
use aegis_core::{
    tunnel_policy::{ANCHOR_V4, ANCHOR_V6},
    RelaySettings,
};
use serde_json::json;
use smoltcp::{
    iface::{Config, Interface, SocketHandle, SocketSet},
    phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken},
    socket::{tcp, udp},
    time::Instant as SmolInstant,
    wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint},
};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
const LISTENERS_PER_PORT: usize = 4;
const MAX_PORTS: usize = 128;
const TCP_SOCK_BUF: usize = 16 * 1024;
const MAX_PACKET_QUEUE: usize = 512;
/// The engine's synthetic IPv4 pool. 198.19.0.0/16 holds the tunnel's own
/// addresses and anchors and is never given out. There is no synthetic IPv6
/// range: AAAA queries are relayed (real answers, carried as numeric
/// targets); an IPv4-mapped IPv6 destination of this pool is the same
/// binding as its IPv4 address (`lease_target_host`).
const FAKE_IP_POOL: &str = "198.18.0.0/16";
/// The TTL of the engine's A answers.
pub const FAKE_IP_ANSWER_TTL_SECS: u32 = 60;
/// How long an answered address must be unused (no DNS answer, no flow, no
/// queued reply) before it may be given to another name, and then only when
/// the pool has no address left that was never given out. B-06 build 37
/// endurance: the engine had forgotten answers 60 s after them while macOS's
/// resolver served them for longer (its unicast cache keeps an answer past
/// its TTL; a 60 s answer was used 67.6 s after it arrived), and
/// applications keep the addresses getaddrinfo gave them on their own clocks
/// (about a minute in common browsers). An hour leaves every one of those far
/// behind and still recycles a pool that heavy use fills (65,533 names).
pub const FAKE_IP_RECYCLE_IDLE: Duration = Duration::from_secs(3600);
const _: () = assert!(FAKE_IP_RECYCLE_IDLE.as_secs() >= 60 * FAKE_IP_ANSWER_TTL_SECS as u64);

pub use crate::packet_engine_io::{PacketIo, TunnelStats};
include!("phy_body.rs");
struct TcpFlow {
    handle: SocketHandle,
    bridge: std::net::TcpStream,
    last_active: Instant,
    pump: TcpStreamPump,
    /// The connection this flow was promoted for: its original destination
    /// and the app's endpoint.
    local: IpEndpoint,
    remote: Option<IpEndpoint>,
    #[cfg(test)]
    last_state: tcp::State,
}

#[cfg(test)]
fn trace_test_tcp(direction: &str, packet: &[u8]) {
    use super::linux_nfqueue::{decode_tcp, DecodedTcp};
    if let Ok(decoded) = decode_tcp(packet) {
        let flags = match decoded {
            DecodedTcp::V4(tcp) => tcp.tcp_flags,
            DecodedTcp::V6(tcp) => tcp.tcp_flags,
        };
        if flags & 7 != 0 || packet.len() > 1500 {
            eprintln!("native TCP {direction}: bytes={} {decoded:?}", packet.len());
        }
    }
}
struct UdpReply {
    port: u16,
    src: IpEndpoint,
    orig_dst: IpAddress,
    resp: Vec<u8>,
    generation: u64,
}
struct UdpFlow {
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    last_active: Instant,
    job: tokio::task::JoinHandle<()>,
    generation: u64,
}
impl Drop for UdpFlow {
    fn drop(&mut self) {
        self.job.abort();
    }
}

#[derive(Clone)]
struct Dns {
    services: Arc<dyn RelayServices>,
    map: Arc<FakeIpMap>,
    upstream: std::net::SocketAddr,
}
impl Dns {
    fn is_resolver(&self, target: IpEndpoint) -> bool {
        target.port == 53
            && (target.addr == IpAddress::from(ANCHOR_V4)
                || target.addr == IpAddress::from(ANCHOR_V6))
    }
    async fn answer(&self, settings: &RelaySettings, request: &[u8]) -> Vec<u8> {
        if dns_preview::question_type(request).is_none_or(|q| q == 1) {
            return dns_preview::build_response_with_sink(
                request,
                &self.map,
                FAKE_IP_ANSWER_TTL_SECS,
                &*self.services,
            );
        }
        self.services
            .udp_once(
                settings,
                crate::relay_runtime_types::ConnectTarget {
                    host: self.upstream.ip().to_string(),
                    port: self.upstream.port(),
                },
                request,
            )
            .await
            .ok()
            .filter(|r| aegis_core::dns_response::is_valid_relay_response(request, r))
            .unwrap_or_else(|| dns_preview::dns_error_response(request, 2))
    }
}

// Connect and authenticate both halves before exposing them to the asynchronous
// relay task. A competing localhost connection can never become this bridge.
fn stream_pair() -> io::Result<(std::net::TcpStream, std::net::TcpStream)> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let client = std::net::TcpStream::connect(listener.local_addr()?)?;
    let expected = client.local_addr()?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match listener.accept() {
            Ok((server, peer)) if peer == expected => {
                client.set_nonblocking(true)?;
                server.set_nonblocking(true)?;
                return Ok((client, server));
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => std::thread::yield_now(),
            Err(e) => return Err(e),
        }
        if Instant::now() > deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
    }
}

/// The fake-IP map of every engine this process runs. An engine run ends with
/// its session (a lost carrier, a re-pin, a rebuild) while the tunnel's DNS
/// settings, the system resolver's cache and every application's cached
/// answers stay: a map of its own would give the next run's first answers
/// the very addresses those caches still hold for other names. The map is
/// bounded by its pool.
fn engine_fake_ips() -> io::Result<Arc<FakeIpMap>> {
    static MAP: std::sync::OnceLock<Arc<FakeIpMap>> = std::sync::OnceLock::new();
    if let Some(map) = MAP.get() {
        return Ok(map.clone());
    }
    // A new process starts its never-used addresses at a random offset, so
    // an earlier process's first answers are not the first given out again.
    let map = FakeIpMap::new(FAKE_IP_POOL, FAKE_IP_RECYCLE_IDLE)
        .map_err(io::Error::other)?
        .starting_at(rand::random());
    Ok(MAP.get_or_init(|| Arc::new(map)).clone())
}

#[allow(clippy::too_many_arguments)]
pub fn run_ready_with_services(
    device: &mut impl PacketIo,
    settings: RelaySettings,
    services: Arc<dyn RelayServices>,
    stop: Arc<AtomicBool>,
    max_flows: usize,
    idle: Duration,
    mtu: usize,
    dns_upstream: std::net::SocketAddr,
    ready: impl FnOnce(),
) -> io::Result<TunnelStats> {
    run_ready_with_fake_ips(
        device,
        settings,
        services,
        stop,
        max_flows,
        idle,
        mtu,
        dns_upstream,
        engine_fake_ips()?,
        ready,
    )
}

/// `run_ready_with_services` over the fake-IP map `fake_ips`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_ready_with_fake_ips(
    device: &mut impl PacketIo,
    settings: RelaySettings,
    services: Arc<dyn RelayServices>,
    stop: Arc<AtomicBool>,
    max_flows: usize,
    idle: Duration,
    mtu: usize,
    dns_upstream: std::net::SocketAddr,
    fake_ips: Arc<FakeIpMap>,
    ready: impl FnOnce(),
) -> io::Result<TunnelStats> {
    if max_flows == 0 || max_flows > 512 || !(1280..=1500).contains(&mtu) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid tunnel limits",
        ));
    }
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    let mut phy = Phy {
        input: VecDeque::new(),
        output: VecDeque::new(),
        mtu,
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = rand::random();
    let mut iface = Interface::new(config, &mut phy, SmolInstant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addresses| {
        addresses.push(IpCidr::new(ANCHOR_V4.into(), 32)).unwrap();
        addresses.push(IpCidr::new(ANCHOR_V6.into(), 128)).unwrap();
    });
    iface
        .routes_mut()
        .add_default_ipv4_route(ANCHOR_V4)
        .unwrap();
    iface
        .routes_mut()
        .add_default_ipv6_route(ANCHOR_V6)
        .unwrap();
    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_listeners = HashMap::new();
    let mut tcp_flows = HashMap::new();
    let mut udp_ports = HashMap::new();
    let mut udp_flows = HashMap::new();
    let (udp_tx, udp_rx) = std::sync::mpsc::sync_channel(256);
    let settings = Arc::new(settings);
    let mut stats = TunnelStats::default();
    let mut sweep = Instant::now();
    let dns = Dns {
        services,
        map: fake_ips,
        upstream: dns_upstream,
    };
    let mut fragments = fragments::Fragments::default();
    ready();
    while !stop.load(Ordering::Acquire) {
        for _ in 0..256 {
            let Some(packet) = device.receive()? else {
                break;
            };
            stats.packets_received += 1;
            #[cfg(test)]
            trace_test_tcp("receive", &packet);
            let packet = match fragments.accept(&packet) {
                Ok(Some(packet)) => packet,
                Ok(None) => continue,
                Err(_) => {
                    stats.packets_dropped += 1;
                    continue;
                }
            };
            // The decoder rejects malformed/fragmented frames rather than
            // accidentally creating a target from unchecked packet offsets.
            let Ok(decoded) = decode_packet(&packet) else {
                stats.packets_dropped += 1;
                continue;
            };
            let port = decoded.dst_port();
            if port == 0 {
                stats.packets_dropped += 1;
                continue;
            }
            match decoded {
                DecodedPacket::Tcp(_)
                    if tcp_flows.len() + tcp_flows_pending(&tcp_listeners) < max_flows * 2 =>
                {
                    ensure_tcp_listeners(&mut sockets, &mut tcp_listeners, port)
                }
                DecodedPacket::Udp(_) => ensure_udp_socket(&mut sockets, &mut udp_ports, port),
                _ => {}
            }
            if phy.input.len() < MAX_PACKET_QUEUE {
                phy.input.push_back(packet);
            } else {
                stats.packets_dropped += 1;
            }
        }
        iface.poll(SmolInstant::now(), &mut phy, &mut sockets);
        promote_tcp_flows(
            &mut sockets,
            &mut tcp_listeners,
            &mut tcp_flows,
            &rt,
            &settings,
            max_flows,
            &mut stats,
            &dns,
        );
        pump_tcp_flows(&mut sockets, &mut tcp_flows, &mut stats);
        service_udp(
            &mut sockets,
            &udp_ports,
            &mut udp_flows,
            &rt,
            &settings,
            &udp_tx,
            max_flows,
            &mut stats,
            &dns,
        );
        inject_udp_replies(
            device,
            &udp_rx,
            &mut stats,
            mtu,
            &mut udp_flows,
            &*dns.services,
        )?;
        replenish_listeners(&mut sockets, &mut tcp_listeners);
        // Poll once more after data is queued; otherwise a quiet application
        // should not have to produce another packet to receive its response.
        iface.poll(SmolInstant::now(), &mut phy, &mut sockets);
        while let Some(packet) = phy.output.pop_front() {
            #[cfg(test)]
            trace_test_tcp("send", &packet);
            match device.send(&packet) {
                Ok(()) => stats.packets_sent += 1,
                Err(error)
                    if error.raw_os_error() == Some(111)
                        || error.kind() == io::ErrorKind::WouldBlock =>
                {
                    stats.packets_dropped += 1;
                }
                Err(error) => return Err(error),
            }
        }
        if sweep.elapsed() >= Duration::from_secs(1) {
            reap(&mut udp_flows, idle);
            udp_ports.retain(|port, handle| {
                if udp_flows.keys().any(|(_, dst)| dst.port == *port) {
                    true
                } else {
                    sockets.remove(*handle);
                    false
                }
            });
            tcp_listeners.retain(|port, pool| {
                if tcp_flows.values().any(|flow| {
                    sockets
                        .get::<tcp::Socket>(flow.handle)
                        .local_endpoint()
                        .is_some_and(|dst| dst.port == *port)
                }) {
                    true
                } else {
                    for handle in pool.drain(..) {
                        sockets.remove(handle);
                    }
                    false
                }
            });
            for flow in tcp_flows.values() {
                if flow.last_active.elapsed() > idle {
                    sockets.get_mut::<tcp::Socket>(flow.handle).abort();
                }
            }
            sweep = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(stats)
}
fn tcp_flows_pending(tcp_listeners: &HashMap<u16, Vec<SocketHandle>>) -> usize {
    tcp_listeners.values().map(|v| v.len()).sum()
}

fn new_tcp_listener(sockets: &mut SocketSet, port: u16) -> Option<SocketHandle> {
    let sock = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0u8; TCP_SOCK_BUF]),
        tcp::SocketBuffer::new(vec![0u8; TCP_SOCK_BUF]),
    );
    let handle = sockets.add(sock);
    // Port-only listen (addr = None) so the socket accepts any destination and
    // records the original (D,port) in its tuple for recovery.
    if sockets.get_mut::<tcp::Socket>(handle).listen(port).is_err() {
        sockets.remove(handle);
        return None;
    }
    Some(handle)
}

fn ensure_tcp_listeners(
    sockets: &mut SocketSet,
    tcp_listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    port: u16,
) {
    if !tcp_listeners.contains_key(&port) && tcp_listeners.len() >= MAX_PORTS {
        return;
    }
    let pool = tcp_listeners.entry(port).or_default();
    while pool.len() < LISTENERS_PER_PORT {
        match new_tcp_listener(sockets, port) {
            Some(h) => pool.push(h),
            None => break,
        }
    }
}

fn ensure_udp_socket(
    sockets: &mut SocketSet,
    udp_ports: &mut HashMap<u16, SocketHandle>,
    port: u16,
) {
    if udp_ports.contains_key(&port) || udp_ports.len() >= MAX_PORTS {
        return;
    }
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65_535]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 65_535]);
    let mut sock = udp::Socket::new(rx, tx);
    if sock.bind(port).is_ok() {
        let handle = sockets.add(sock);
        udp_ports.insert(port, handle);
    }
}

/// Move any listener that caught a SYN (now active with a recorded tuple) into a
/// relayed flow, bridging it to the relay tunnel for its ORIGINAL destination.
#[allow(clippy::too_many_arguments)]
fn promote_tcp_flows(
    sockets: &mut SocketSet,
    tcp_listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    rt: &tokio::runtime::Runtime,
    settings: &Arc<RelaySettings>,
    max_flows: usize,
    stats: &mut TunnelStats,
    dns: &Dns,
) {
    // Promote the instant a listener leaves Listen — i.e. it caught a SYN and now
    // has a recorded (orig_dst, src) tuple, even if still mid-handshake
    // (SynReceived). Waiting for may_send()/Established would race
    // replenish_listeners, which evicts non-Listen sockets from the pool and would
    // orphan the connection (established + ACKing but never relayed).
    //
    // A RST in SYN-RECEIVED (an app that gave up its connect before the
    // SYN-ACK arrived) returns a smoltcp socket to LISTEN with its tuple
    // cleared, where it accepts the port's next SYN for ANY destination.
    // Such a socket no longer carries the connection its flow was promoted
    // for: end that flow (dropping its bridge ends its relay work) and
    // return the socket to its port's listeners, so a connection it has
    // accepted since is promoted below, to its own destination.
    let reverted: Vec<SocketHandle> = tcp_flows
        .values()
        .filter(|flow| {
            let s = sockets.get::<tcp::Socket>(flow.handle);
            match s.state() {
                tcp::State::Listen => true,
                tcp::State::Closed | tcp::State::TimeWait => false,
                _ => s.local_endpoint() != Some(flow.local) || s.remote_endpoint() != flow.remote,
            }
        })
        .map(|flow| flow.handle)
        .collect();
    for handle in reverted {
        if let Some(flow) = tcp_flows.remove(&handle) {
            tcp_listeners
                .entry(flow.local.port)
                .or_default()
                .push(handle);
        }
    }
    let mut promoted: Vec<(u16, SocketHandle)> = Vec::new();
    for (port, pool) in tcp_listeners.iter() {
        for &handle in pool.iter() {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            if !matches!(s.state(), tcp::State::Listen | tcp::State::Closed)
                && s.local_endpoint().is_some()
            {
                promoted.push((*port, handle));
            }
        }
    }
    for (port, handle) in promoted {
        // Remove from the listener pool (it is now a flow socket).
        if let Some(pool) = tcp_listeners.get_mut(&port) {
            pool.retain(|&h| h != handle);
        }
        if tcp_flows.len() >= max_flows {
            // At capacity: abort (RST) rather than leak. Fail-closed.
            sockets.get_mut::<tcp::Socket>(handle).abort();
            sockets.remove(handle);
            continue;
        }
        let (orig_dst, src) = {
            let s = sockets.get_mut::<tcp::Socket>(handle);
            (s.local_endpoint(), s.remote_endpoint())
        };
        let Some(orig_dst) = orig_dst else {
            sockets.remove(handle);
            continue;
        };
        match open_relay_bridge(rt, settings, orig_dst, dns) {
            Ok(bridge) => {
                stats.tcp_flows_opened += 1;
                dns.services.emit(
                    "info",
                    RuntimeEventCode::WideTunSmoltcpTcpFlowEstablished,
                    "wide tun engine tcp flow established (multi-target)",
                    json!({
                        "orig_dst": orig_dst.to_string(),
                        "src": src.map(|e| e.to_string()).unwrap_or_default(),
                    }),
                );
                tcp_flows.insert(
                    handle,
                    TcpFlow {
                        handle,
                        bridge,
                        last_active: Instant::now(),
                        pump: TcpStreamPump::default(),
                        local: orig_dst,
                        remote: src,
                        #[cfg(test)]
                        last_state: tcp::State::Listen,
                    },
                );
            }
            Err(e) => {
                #[cfg(test)]
                eprintln!("native tunnel bridge construction failed: {e}");
                // Relay bridge could not be opened: drop the flow (fail-closed).
                dns.services.emit(
                    "warn",
                    RuntimeEventCode::WideNfqueueBackendError,
                    "wide tun engine tcp relay bridge failed (fail-closed)",
                    json!({ "orig_dst": orig_dst.to_string(), "error": e }),
                );
                sockets.get_mut::<tcp::Socket>(handle).abort();
                sockets.remove(handle);
            }
        }
    }
}

/// Open a localhost bridge and spawn the relay tunnel carrying it to `orig_dst`.
fn open_relay_bridge(
    rt: &tokio::runtime::Runtime,
    settings: &Arc<RelaySettings>,
    orig_dst: IpEndpoint,
    dns: &Dns,
) -> Result<std::net::TcpStream, String> {
    let (bridge, server) = stream_pair().map_err(|e| e.to_string())?;
    let settings = settings.clone();
    let port = orig_dst.port;
    let resolver = dns.is_resolver(orig_dst);
    let (host, lease) = if resolver {
        (String::new(), None)
    } else {
        lease_target_host(
            std::net::SocketAddr::new(orig_dst.addr.into(), port),
            Some(&dns.map),
        )
        .map_err(|e| e.to_string())?
    };
    let dns = dns.clone();
    rt.spawn(async move {
        let _lease = lease;
        if let Ok(mut stream) = tokio::net::TcpStream::from_std(server) {
            if resolver {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                loop {
                    let work = async {
                        let length = stream.read_u16().await?;
                        if length < 12 {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        let mut request = vec![0; length as usize];
                        stream.read_exact(&mut request).await?;
                        let response = if dns_preview::question_type(&request)
                            .is_none_or(|q| q == 1)
                        {
                            dns.answer(&settings, &request).await
                        } else {
                            // TCP DNS preserves framing and large replies through
                            // the same authenticated stream transport as web traffic.
                            let (local, remote) = stream_pair()?;
                            let mut local = tokio::net::TcpStream::from_std(local)?;
                            let remote = tokio::net::TcpStream::from_std(remote)?;
                            let relay = settings.clone();
                            let upstream = dns.upstream;
                            let services = dns.services.clone();
                            let task = tokio::spawn(async move {
                                let _ = services
                                    .tcp(remote, &relay, upstream.ip().to_string(), upstream.port())
                                    .await;
                            });
                            let result = async {
                                local.write_u16(length).await?;
                                local.write_all(&request).await?;
                                let n = local.read_u16().await?;
                                let mut r = vec![0; n as usize];
                                local.read_exact(&mut r).await?;
                                if !aegis_core::dns_response::is_valid_relay_response(&request, &r)
                                {
                                    return Err(io::ErrorKind::InvalidData.into());
                                }
                                Ok::<_, io::Error>(r)
                            }
                            .await;
                            task.abort();
                            result?
                        };
                        stream.write_u16(response.len() as u16).await?;
                        stream.write_all(&response).await?;
                        Ok::<_, io::Error>(())
                    };
                    if !matches!(
                        tokio::time::timeout(Duration::from_secs(30), work).await,
                        Ok(Ok(()))
                    ) {
                        break;
                    }
                }
            } else {
                let _result = dns.services.tcp(stream, &settings, host, port).await;
                #[cfg(test)]
                if let Err(error) = _result {
                    eprintln!("native tunnel test relay bridge failed: {error:#}");
                }
            }
        }
    });
    Ok(bridge)
}

/// Pump bytes between each smoltcp TCP socket and its localhost relay bridge.
fn pump_tcp_flows(
    sockets: &mut SocketSet,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    stats: &mut TunnelStats,
) {
    let mut closed: Vec<SocketHandle> = Vec::new();
    for flow in tcp_flows.values_mut() {
        let s = sockets.get_mut::<tcp::Socket>(flow.handle);
        #[cfg(test)]
        if s.state() != flow.last_state {
            eprintln!(
                "native TCP state {:?}: {:?} -> {:?}, recv={}, send={}",
                flow.handle,
                flow.last_state,
                s.state(),
                s.recv_queue(),
                s.send_queue()
            );
            flow.last_state = s.state();
        }
        // A previous poll delivered the final ACK/RST. Do not remove a newly
        // closed socket before smoltcp can drain queued response bytes and FIN.
        if TcpStreamPump::removable(s) {
            closed.push(flow.handle);
            continue;
        }
        match flow.pump.pump(s, &mut flow.bridge) {
            Ok(progress) => {
                stats.tcp_egress_bytes += progress.to_client as u64;
                if progress.to_client > 0 || progress.to_relay > 0 {
                    flow.last_active = Instant::now();
                }
                if progress.shutdown_relay_write
                    && flow.bridge.shutdown(std::net::Shutdown::Write).is_err()
                {
                    s.abort();
                }
            }
            // Leave the aborted socket until the next interface poll emits RST.
            Err(_error) => {
                #[cfg(test)]
                eprintln!(
                    "native tunnel test pump failed: {:?}, state={:?}, recv={}, send={}",
                    _error,
                    s.state(),
                    s.recv_queue(),
                    s.send_queue()
                );
                s.abort();
            }
        }
    }
    for h in closed {
        if let Some(_flow) = tcp_flows.remove(&h) {
            let s = sockets.get_mut::<tcp::Socket>(h);
            s.close();
            sockets.remove(h);
        }
    }
}

/// Capture UDP datagrams and route each into a PERSISTENT per-flow MASQUE
/// CONNECT-UDP session (one QUIC session per `(src, dst)`, reused for every
/// datagram — so multi-datagram UDP like QUIC/HTTP3 works, not only single-shot
/// DNS). New flows lazily spawn the session; responses return over `udp_tx`.
#[allow(clippy::too_many_arguments)]
fn service_udp(
    sockets: &mut SocketSet,
    udp_ports: &HashMap<u16, SocketHandle>,
    udp_flows: &mut HashMap<(IpEndpoint, IpEndpoint), UdpFlow>,
    rt: &tokio::runtime::Runtime,
    settings: &Arc<RelaySettings>,
    udp_tx: &std::sync::mpsc::SyncSender<UdpReply>,
    max_flows: usize,
    stats: &mut TunnelStats,
    dns: &Dns,
) {
    for (&port, &handle) in udp_ports.iter() {
        loop {
            let captured = {
                let s = sockets.get_mut::<udp::Socket>(handle);
                if !s.can_recv() {
                    break;
                }
                match s.recv() {
                    Ok((data, meta)) => Some((data.to_vec(), meta.endpoint, meta.local_address)),
                    Err(_) => None,
                }
            };
            let Some((payload, src, local)) = captured else {
                break;
            };
            // The carry target is the ORIGINAL destination the datagram was sent
            // to, recovered from smoltcp metadata — NOT a fixed host.
            let Some(orig_dst_ip) = local else {
                continue; // no original destination -> cannot carry, drop
            };
            let key = (src, IpEndpoint::new(orig_dst_ip, port));
            if udp_flows
                .get(&key)
                .is_some_and(|f| f.outbound_tx.is_closed())
            {
                udp_flows.remove(&key);
            }
            // Existing flow: feed the datagram into its persistent session.
            if let Some(flow) = udp_flows.get_mut(&key) {
                flow.last_active = Instant::now();
                let _ = flow.outbound_tx.try_send(payload); // drop on backpressure (UDP)
                continue;
            }
            // New flow: at capacity -> drop (fail-closed), never native.
            if udp_flows.len() >= max_flows {
                continue;
            }
            // Spawn ONE persistent MASQUE CONNECT-UDP session for this flow. A
            // forwarder tags each response with this flow's (src, dst) and hands it
            // to the poll loop for smoltcp injection.
            let (out_tx, mut out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
            let (in_tx, mut in_rx) =
                tokio::sync::mpsc::channel::<crate::relay_runtime_types::UdpPacket>(8);
            let reply_tx = udp_tx.clone();
            let generation = rand::random();
            rt.spawn(async move {
                while let Some(pkt) = in_rx.recv().await {
                    if reply_tx
                        .try_send(UdpReply {
                            port,
                            src,
                            orig_dst: orig_dst_ip,
                            resp: pkt.payload,
                            generation,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            });
            let settings = settings.clone();
            let resolver = dns.is_resolver(key.1);
            let (host, lease) = if resolver {
                (String::new(), None)
            } else {
                match lease_target_host(
                    std::net::SocketAddr::new(orig_dst_ip.into(), port),
                    Some(&dns.map),
                ) {
                    Ok(value) => value,
                    Err(_) => continue,
                }
            };
            let task_dns = dns.clone();
            let job = rt.spawn(async move {
                let _lease = lease;
                // Fail-closed: a failed/ended session just stops; no native egress.
                if resolver {
                    while let Some(request) = out_rx.recv().await {
                        let payload = task_dns.answer(&settings, &request).await;
                        let packet = crate::relay_runtime_types::UdpPacket {
                            target: crate::relay_runtime_types::ConnectTarget {
                                host: orig_dst_ip.to_string(),
                                port,
                            },
                            payload,
                        };
                        if in_tx.send(packet).await.is_err() {
                            break;
                        }
                    }
                } else {
                    let _ = task_dns
                        .services
                        .udp_flow(&settings, &host, port, out_rx, in_tx)
                        .await;
                }
            });
            let _ = out_tx.try_send(payload);
            udp_flows.insert(
                key,
                UdpFlow {
                    outbound_tx: out_tx,
                    last_active: Instant::now(),
                    job,
                    generation,
                },
            );
            stats.udp_sessions_opened += 1;
            dns.services.emit(
                "info",
                RuntimeEventCode::Ipv6UdpSessionCreated,
                "wide tun engine ipv6 udp flow session created (persistent policy-ordered relay)",
                json!({ "src": src.to_string(), "orig_dst": format!("[{orig_dst_ip}]:{port}") }),
            );
        }
    }
}

/// Inject any ready MASQUE replies back into smoltcp, sourced from the original
/// destination so the application accepts them.
fn inject_udp_replies(
    device: &mut impl PacketIo,
    udp_rx: &std::sync::mpsc::Receiver<UdpReply>,
    stats: &mut TunnelStats,
    mtu: usize,
    flows: &mut HashMap<(IpEndpoint, IpEndpoint), UdpFlow>,
    services: &dyn RelayServices,
) -> io::Result<()> {
    while let Ok(reply) = udp_rx.try_recv() {
        let Some(flow) = flows
            .get_mut(&(reply.src, IpEndpoint::new(reply.orig_dst, reply.port)))
            .filter(|flow| flow.generation == reply.generation)
        else {
            continue;
        };
        flow.last_active = Instant::now();
        let packets = fragments::udp_packets(
            reply.orig_dst.into(),
            reply.port,
            reply.src.addr.into(),
            reply.src.port,
            &reply.resp,
            mtu,
        )?;
        let mut sent = true;
        for packet in packets {
            match device.send(&packet) {
                Ok(()) => stats.packets_sent += 1,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock || e.raw_os_error() == Some(111) =>
                {
                    sent = false;
                    stats.packets_dropped += 1;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        if sent {
            stats.udp_egress_bytes += reply.resp.len() as u64;
            services.emit(
                "info",
                RuntimeEventCode::Ipv6UdpResponseDelivered,
                "wide tun engine ipv6 udp response delivered (bidirectional)",
                json!({ "src": reply.src.to_string(), "response_len": reply.resp.len() }),
            );
        }
    }
    Ok(())
}

/// Top up each port's listener pool so re-armed listeners are ready for the next
/// connection to that port.
fn replenish_listeners(
    sockets: &mut SocketSet,
    tcp_listeners: &mut HashMap<u16, Vec<SocketHandle>>,
) {
    let ports: Vec<u16> = tcp_listeners.keys().copied().collect();
    for port in ports {
        // Drop any listener that died (e.g. was reset) before topping up.
        if let Some(pool) = tcp_listeners.get_mut(&port) {
            pool.retain(|&h| {
                let live = matches!(
                    sockets.get_mut::<tcp::Socket>(h).state(),
                    tcp::State::Listen
                );
                if !live {
                    sockets.remove(h);
                }
                live
            });
        }
        ensure_tcp_listeners(sockets, tcp_listeners, port);
    }
}

/// Reap idle UDP flows (TCP flows reap themselves on close). Dropping a `UdpFlow`
/// drops its `outbound_tx`, which closes the session's `outbound_rx` and ends the
/// persistent MASQUE QUIC session cleanly.
fn reap(udp_flows: &mut HashMap<(IpEndpoint, IpEndpoint), UdpFlow>, idle_timeout: Duration) {
    let now = Instant::now();
    udp_flows.retain(|_, flow| now.duration_since(flow.last_active) < idle_timeout);
}

#[cfg(test)]
#[path = "engine_fake_ip_tests.rs"]
mod fake_ip_tests;
