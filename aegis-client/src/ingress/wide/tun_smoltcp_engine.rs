//! Production multi-flow IPv6 TUN + smoltcp relay backend.
//!
//! Unlike the controlled single-target lab in [`super::tun_smoltcp_adapter`]
//! (one `/128`, one listening port, one fixed relay target, clamped to 1–600s),
//! this is the **production** backend for the `full-wide-tun` product mode:
//!
//! - captures **any** IPv6 destination via smoltcp's any-ip transparent path
//!   (`set_any_ip(true)` + a default route through an AEGIS-owned anchor), so a
//!   single interface answers for the whole `::/0` space without enumerating
//!   `/128`s,
//! - demultiplexes **many concurrent flows**: a TCP listener pool per observed
//!   destination port and a UDP socket per port, each captured flow bridged to
//!   its OWN relay target = the original destination it was trying to reach
//!   (recovered from the smoltcp socket, not a fixed host),
//! - is **long-lived** (no time budget): it runs until the shared `stop` flag is
//!   set (SIGTERM/SIGINT) and is protected by a stall-detector watchdog that
//!   force-removes the capture if the engine thread ever wedges or dies, and by
//!   RAII rollback on every exit path,
//! - is **fail-closed**: a relay error drops that flow; IPv6 never egresses
//!   natively. The real `::/0` default is preserved (we install `::/1` +
//!   `8000::/1`, more specific than the default but not a delete), and any IPv6
//!   relay endpoint that cannot be excluded refuses the start.
//!
//! See the archived `linux-tun-smoltcp-ipv6-relay-design.md` design baseline and the plan in
//! `full-wide-tun` for the verified smoltcp 0.12 mechanism.

#![cfg(target_os = "linux")]

use super::linux_nfqueue::{decode_packet, DecodedPacket};
use super::tcp_stream_pump::TcpStreamPump;
use super::tun_smoltcp::TunDevice;
use crate::runtime_events::RuntimeEventCode;
use crate::runtime_jsonl;
use aegis_core::RelaySettings;
use serde_json::json;
use smoltcp::iface::{Config, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, PacketMeta, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, Ipv6Address};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TUN_MTU: usize = 1500;
/// Idle listening sockets kept armed per observed destination port so a burst of
/// concurrent connections to the same port does not get RST'd while a single
/// listener is being re-armed.
const LISTENERS_PER_PORT: usize = 4;
/// Hard cap on concurrent live flows; new flows past this are RST'd (fail-closed),
/// never leaked. smoltcp socket storage is bounded, so this also bounds memory.
const DEFAULT_MAX_FLOWS: usize = 512;
const TCP_SOCK_BUF: usize = 16 * 1024;

/// Configuration for the production TUN engine.
pub struct TunEngineConfig {
    /// AEGIS-owned TUN interface name (non-persistent; removed on teardown).
    pub ifname: String,
    /// The single IPv6 address smoltcp owns; also the gateway of the in-stack
    /// default route, which is what makes any-ip transparent accept work.
    pub anchor: Ipv6Address,
    /// Relay settings used for TCP and policy-ordered UDP relay transports.
    pub relay_settings: RelaySettings,
    /// Relay/control endpoints kept OFF the TUN (loop avoidance). IPv4 entries are
    /// unaffected by the IPv6 capture; an IPv6 entry that cannot be excluded
    /// refuses the start.
    pub relay_excludes: Vec<IpAddr>,
    /// A UDP session with no datagram for this long is reaped.
    pub idle_timeout: Duration,
    /// Max concurrent flows before new ones are RST'd (fail-closed).
    pub max_flows: usize,
    /// If the engine heartbeat does not advance for this long, the watchdog
    /// force-removes the capture (stall detector — NOT a runtime budget).
    pub watchdog_stall: Duration,
    /// Explicit controlled startup; closed input is discarded, revoke is permanent.
    pub(crate) forward_gate: Option<super::forward_gate::ForwardGate>,
}

impl TunEngineConfig {
    pub fn new(relay_settings: RelaySettings) -> Self {
        Self {
            ifname: "aegis-tun0".to_string(),
            anchor: Ipv6Address::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 1),
            relay_settings,
            relay_excludes: Vec::new(),
            idle_timeout: Duration::from_secs(30),
            max_flows: DEFAULT_MAX_FLOWS,
            watchdog_stall: Duration::from_secs(10),
            forward_gate: None,
        }
    }
}

/// Stats returned when the engine stops cleanly.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct TunEngineStats {
    pub tcp_flows_opened: u64,
    pub udp_sessions_opened: u64,
    pub tcp_egress_bytes: u64,
    pub udp_egress_bytes: u64,
    pub clean_teardown: bool,
}

fn run_ip(args: &[&str]) -> std::io::Result<bool> {
    Ok(Command::new("ip").args(args).status()?.success())
}

fn require_ip(args: &[&str]) -> Result<(), String> {
    if run_ip(args).unwrap_or(false) {
        Ok(())
    } else {
        Err("BLOCKED_BY_TUN_ROUTE: required capture command failed".to_owned())
    }
}

/// Best-effort delete of an IPv6 exclude route (`"<prefix> via <gw> dev <dev>"`),
/// used to make exclude installation idempotent against a route left behind by a
/// prior SIGKILL/hard-crash. Ignores failure (route simply absent).
fn del_ip6_route(route: &str) {
    let argv: Vec<&str> = std::iter::once("-6")
        .chain(std::iter::once("route"))
        .chain(std::iter::once("del"))
        .chain(route.split_whitespace())
        .collect();
    let _ = run_ip(&argv);
}

/// Best-effort discovery of the current IPv6 default gateway + WAN device, used to
/// pin an IPv6 relay exclude back onto the real path. Returns None if there is no
/// IPv6 default route.
fn ipv6_default_gw_dev() -> Option<(String, String)> {
    let out = Command::new("ip")
        .args(["-6", "route", "show", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    parse_default_gw_dev(&text)
}

/// Parse `default via <gw> dev <dev> ...` from `ip -6 route show default`.
fn parse_default_gw_dev(text: &str) -> Option<(String, String)> {
    for line in text.lines() {
        let toks: Vec<&str> = line.split_whitespace().collect();
        let mut gw = None;
        let mut dev = None;
        let mut i = 0;
        while i + 1 < toks.len() {
            match toks[i] {
                "via" => gw = Some(toks[i + 1].to_string()),
                "dev" => dev = Some(toks[i + 1].to_string()),
                _ => {}
            }
            i += 1;
        }
        if let (Some(g), Some(d)) = (gw, dev) {
            return Some((g, d));
        }
    }
    None
}

/// RAII teardown: removes the AEGIS-added `::/1` + `8000::/1` capture halves, the
/// per-exclude pin routes, and the (non-persistent) TUN interface. The real
/// `::/0` default is never deleted, so dropping this restores baseline routing.
#[derive(Clone)]
struct EngineRouteGuard {
    ifname: String,
    exclude_routes: Vec<String>,
    torn_down: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
}

impl EngineRouteGuard {
    fn teardown(&self) {
        self.stop.store(true, Ordering::SeqCst);
        if self.torn_down.swap(true, Ordering::SeqCst) {
            return; // already done by the watchdog (or a prior drop)
        }
        let _ = run_ip(&["-6", "route", "del", "::/1", "dev", &self.ifname]);
        let _ = run_ip(&["-6", "route", "del", "8000::/1", "dev", &self.ifname]);
        for r in &self.exclude_routes {
            let argv: Vec<&str> = std::iter::once("-6")
                .chain(std::iter::once("route"))
                .chain(std::iter::once("del"))
                .chain(r.split_whitespace())
                .collect();
            let _ = run_ip(&argv);
        }
        let _ = run_ip(&["link", "del", &self.ifname]);
        runtime_jsonl::emit(
            "info",
            RuntimeEventCode::WideTunSmoltcpCleanupCompleted,
            "wide tun engine cleanup completed (capture removed, real ::/0 preserved)",
            json!({
                "ifname": self.ifname,
                "removed": ["::/1", "8000::/1"],
                "excludes_removed": self.exclude_routes.len(),
                "scope": "aegis_owned_only",
                "real_default_preserved": true,
            }),
        );
    }
}

impl Drop for EngineRouteGuard {
    fn drop(&mut self) {
        self.teardown();
    }
}

/// smoltcp phy::Device that serves RX from a pre-filled injection queue (so the
/// engine can peek every frame and arm a listener BEFORE smoltcp processes it —
/// smoltcp RSTs any TCP segment with no accepting socket) and writes TX straight
/// to the TUN fd.
struct PeekTunPhy {
    fd: i32,
    inject: VecDeque<Vec<u8>>,
}

struct TunRx {
    buf: Vec<u8>,
}
struct TunTx {
    fd: i32,
}

impl Device for PeekTunPhy {
    type RxToken<'a>
        = TunRx
    where
        Self: 'a;
    type TxToken<'a>
        = TunTx
    where
        Self: 'a;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let buf = self.inject.pop_front()?;
        Some((TunRx { buf }, TunTx { fd: self.fd }))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<Self::TxToken<'_>> {
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

/// One captured TCP flow: a smoltcp socket bridged over localhost to the relay
/// tunnel carrying it to the original destination.
struct TcpFlow {
    handle: SocketHandle,
    bridge: std::net::TcpStream,
    last_active: Instant,
    pump: TcpStreamPump,
    /// The connection this flow was promoted for: its original destination
    /// and the app's endpoint.
    local: IpEndpoint,
    remote: Option<IpEndpoint>,
}

/// A MASQUE UDP reply produced off-thread, to be injected back into smoltcp on the
/// poll thread (smoltcp is single-threaded).
struct UdpReply {
    port: u16,
    src: IpEndpoint,
    orig_dst: IpAddress,
    resp: Vec<u8>,
}

/// One captured IPv6 UDP flow, keyed by (app src, original dst). Holds the send
/// side of a PERSISTENT MASQUE CONNECT-UDP session (one QUIC session per flow,
/// reused for every datagram — so multi-datagram UDP like QUIC/HTTP3 works, not
/// just single-shot DNS). Dropping it closes the channel, ending the session.
struct UdpFlow {
    outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    last_active: Instant,
    next_open_at: Instant,
}

const UDP_FLOW_RECONNECT_COOLDOWN: Duration = Duration::from_secs(1);

impl UdpFlow {
    fn new(outbound_tx: tokio::sync::mpsc::Sender<Vec<u8>>, opened_at: Instant) -> Self {
        Self {
            outbound_tx,
            last_active: opened_at,
            next_open_at: opened_at + UDP_FLOW_RECONNECT_COOLDOWN,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ExistingUdpFlowSend {
    Queued,
    QueueFull,
    RetryCooldown,
    Missing(Vec<u8>),
    Closed(Vec<u8>),
}

/// Only datagrams rejected by a closed receiver may open a replacement. A
/// full live queue is ordinary UDP loss; it must not duplicate the session.
fn send_to_existing_udp_flow(
    flows: &mut HashMap<(IpEndpoint, IpEndpoint), UdpFlow>,
    key: &(IpEndpoint, IpEndpoint),
    payload: Vec<u8>,
    now: Instant,
) -> ExistingUdpFlowSend {
    let Some(flow) = flows.get_mut(key) else {
        return ExistingUdpFlowSend::Missing(payload);
    };
    match flow.outbound_tx.try_send(payload) {
        Ok(()) => {
            flow.last_active = now;
            ExistingUdpFlowSend::Queued
        }
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            flow.last_active = now;
            ExistingUdpFlowSend::QueueFull
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(payload)) => {
            if now < flow.next_open_at {
                // Continuous traffic must not extend the opening cooldown or
                // keep an ended relay alive through the idle timestamp.
                return ExistingUdpFlowSend::RetryCooldown;
            }
            flows.remove(key);
            ExistingUdpFlowSend::Closed(payload)
        }
    }
}

/// Run the production multi-flow TUN engine until `stop` is set. Blocking entry
/// point (owns its own multi-thread Tokio runtime for relay/MASQUE carries);
/// intended to run on its own thread alongside the v4 REDIRECT + UDP legs.
pub fn run_tun_engine(
    cfg: TunEngineConfig,
    stop: Arc<AtomicBool>,
    ready: crate::wide_workers::WorkerReady,
) -> Result<TunEngineStats, String> {
    if unsafe { libc::geteuid() } != 0 {
        return Err("BLOCKED_BY_TUN_PRIVILEGE: full-wide-tun requires CAP_NET_ADMIN".to_string());
    }
    // Loop-avoidance preflight: an IPv6 relay endpoint we cannot pin off the TUN
    // would capture its own egress. Refuse to start (fail-closed) rather than loop.
    let v6_excludes: Vec<Ipv6Address> = cfg
        .relay_excludes
        .iter()
        .filter_map(|e| match e {
            IpAddr::V6(v6) => Some(*v6), // smoltcp Ipv6Address == std Ipv6Addr in 0.12
            IpAddr::V4(_) => None,       // IPv4 relay is unaffected by the IPv6 capture
        })
        .collect();
    // Always discover the IPv6 default gateway/dev: it pins both any literal-IPv6
    // relay endpoint AND the IPv4-mapped-IPv6 range off the TUN (see below).
    let gw_dev = ipv6_default_gw_dev();
    if !v6_excludes.is_empty() && gw_dev.is_none() {
        return Err(
            "BLOCKED_BY_RELAY_LOOP: IPv6 relay endpoint present but no IPv6 \
             default route to pin it off the TUN (fail-closed)"
                .to_string(),
        );
    }

    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpBackendSelected,
        "wide tun engine selected (production multi-flow IPv6 capture; fail-closed)",
        json!({
            "ifname": cfg.ifname,
            "anchor": cfg.anchor.to_string(),
            "max_flows": cfg.max_flows,
            "v6_excludes": v6_excludes.len(),
        }),
    );

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .map_err(|e| format!("BLOCKED_BY_TUN_RUNTIME: {e}"))?;

    let dev = TunDevice::open(&cfg.ifname).map_err(|e| format!("BLOCKED_BY_TUN_PRIVILEGE: {e}"))?;
    let fd = dev.raw_fd();
    let torn_down = Arc::new(AtomicBool::new(false));
    let mut guard = EngineRouteGuard {
        ifname: cfg.ifname.clone(),
        exclude_routes: Vec::new(),
        torn_down: torn_down.clone(),
        stop: stop.clone(),
    };
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpDeviceCreated,
        "wide tun engine device created",
        json!({ "ifname": dev.name }),
    );

    // --- Kernel capture (long-lived, no time budget) ---
    require_ip(&["link", "set", &cfg.ifname, "up"])?;
    let anchor_cidr = format!("{}/128", cfg.anchor);
    require_ip(&["-6", "addr", "add", &anchor_cidr, "dev", &cfg.ifname])?;

    // Pin IPv6 relay endpoints back onto the real path BEFORE the capture halves
    // (more specific wins), so the tunnel never captures its own egress.
    if let Some((gw, wandev)) = gw_dev.as_ref() {
        // CRITICAL loop-avoidance: the relay leg reaches an IPv4 relay (CF edge,
        // pooled origin) via an IPv4-mapped IPv6 address `::ffff:a.b.c.d` on a
        // dual-stack socket. That range lives inside `::/1`, so without this the
        // capture swallows the relay's OWN egress (live: quinn sendmsg EPERM into
        // the tun). Keep all IPv4-mapped IPv6 on the native path. (Link-local
        // fe80::/10 is already pinned by its kernel /64 route, so NDP to the gw
        // still resolves.)
        let v4mapped = format!("::ffff:0:0/96 via {gw} dev {wandev}");
        // Idempotent install: these exclude pins live on the WAN device, so a prior
        // SIGKILL/hard-crash (where neither the RAII guard nor the watchdog runs)
        // leaves them behind. Delete any stale copy first so the add can't fail with
        // EEXIST — which for a v6 relay exclude below is treated as fatal.
        del_ip6_route(&v4mapped);
        let argv: Vec<&str> = std::iter::once("-6")
            .chain(std::iter::once("route"))
            .chain(std::iter::once("add"))
            .chain(v4mapped.split_whitespace())
            .collect();
        if run_ip(&argv).unwrap_or(false) {
            guard.exclude_routes.push(v4mapped);
        }
        for v6 in &v6_excludes {
            let route = format!("{v6}/128 via {gw} dev {wandev}");
            del_ip6_route(&route);
            let argv: Vec<&str> = std::iter::once("-6")
                .chain(std::iter::once("route"))
                .chain(std::iter::once("add"))
                .chain(route.split_whitespace())
                .collect();
            if run_ip(&argv).unwrap_or(false) {
                guard.exclude_routes.push(route);
            } else {
                // Could not pin an IPv6 relay endpoint — tearing the partial state
                // down and failing closed beats risking a relay loop.
                for r in &guard.exclude_routes {
                    let dargv: Vec<&str> = std::iter::once("-6")
                        .chain(std::iter::once("route"))
                        .chain(std::iter::once("del"))
                        .chain(r.split_whitespace())
                        .collect();
                    let _ = run_ip(&dargv);
                }
                let _ = run_ip(&["link", "del", &cfg.ifname]);
                return Err(format!(
                    "BLOCKED_BY_RELAY_LOOP: failed to pin IPv6 relay exclude {v6} (fail-closed)"
                ));
            }
        }
    }

    require_ip(&["-6", "route", "add", "::/1", "dev", &cfg.ifname])?;
    require_ip(&["-6", "route", "add", "8000::/1", "dev", &cfg.ifname])?;
    runtime_jsonl::emit(
        "info",
        RuntimeEventCode::WideTunSmoltcpRouteInstalled,
        "wide tun engine capture installed (::/1 + 8000::/1; real ::/0 preserved)",
        json!({
            "ifname": cfg.ifname,
            "excludes": guard.exclude_routes.len(),
            "default_route_touched": false,
        }),
    );

    // --- Stall-detector watchdog (production; NOT a runtime budget) ---
    let heartbeat = Arc::new(AtomicU64::new(0));
    let wd_stop = stop.clone();
    let wd_heartbeat = heartbeat.clone();
    let wd_stall = cfg.watchdog_stall;
    let wd_guard = guard.clone();
    let wd_failure = ready.failure_signal();
    let watchdog = std::thread::Builder::new()
        .name("aegis-tun-watchdog".into())
        .spawn(move || {
            let mut last_seen = wd_heartbeat.load(Ordering::SeqCst);
            let mut stalled_for = Duration::ZERO;
            let tick = Duration::from_millis(500);
            loop {
                std::thread::sleep(tick);
                if wd_stop.load(Ordering::SeqCst) {
                    return; // clean stop: the engine's RAII guard tears down
                }
                let hb = wd_heartbeat.load(Ordering::SeqCst);
                if hb == last_seen {
                    stalled_for += tick;
                } else {
                    last_seen = hb;
                    stalled_for = Duration::ZERO;
                }
                if stalled_for >= wd_stall {
                    // Wake the client even if this engine never returns. Its
                    // persistent firewall must keep blocking through restart.
                    wd_failure.report();
                    // Engine wedged/died while stop is still false: force-remove the
                    // capture so a dead engine can never blackhole IPv6. Only REMOVE
                    // (restores real ::/0); never ADD.
                    wd_guard.teardown();
                    runtime_jsonl::emit(
                        "warn",
                        RuntimeEventCode::WideNfqueueBackendError,
                        "wide tun engine watchdog fired (engine stalled; capture removed)",
                        json!({ "ifname": wd_guard.ifname, "stalled_secs": stalled_for.as_secs() }),
                    );
                    wd_stop.store(true, Ordering::SeqCst);
                    return;
                }
            }
        })
        .map_err(|e| format!("BLOCKED_BY_TUN_WATCHDOG: {e}"))?;

    // --- smoltcp interface: any-ip transparent accept over the whole ::/0 ---
    let mut phy = PeekTunPhy {
        fd,
        inject: VecDeque::new(),
    };
    let mut config = Config::new(HardwareAddress::Ip);
    config.random_seed = 0xae61_5c10;
    let mut iface = Interface::new(config, &mut phy, SmolInstant::now());
    iface.set_any_ip(true);
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(cfg.anchor), 128));
    });
    // Default route via the OWNED anchor: routes.lookup(D) -> anchor, and
    // has_ip_addr(anchor) is true, so any-ip accepts an arbitrary destination D.
    let _ = iface.routes_mut().add_default_ipv6_route(cfg.anchor);

    let mut sockets = SocketSet::new(vec![]);
    let mut tcp_listeners: HashMap<u16, Vec<SocketHandle>> = HashMap::new();
    let mut tcp_flows: HashMap<SocketHandle, TcpFlow> = HashMap::new();
    let mut udp_ports: HashMap<u16, SocketHandle> = HashMap::new();
    let mut udp_flows: HashMap<(IpEndpoint, IpEndpoint), UdpFlow> = HashMap::new();

    let (udp_tx, udp_rx) = std::sync::mpsc::sync_channel::<UdpReply>(256);
    let settings = Arc::new(cfg.relay_settings.clone());
    let mut stats = TunEngineStats::default();
    let mut hb: u64 = 0;
    let mut last_sweep = Instant::now();

    ready
        .signal()
        .map_err(|_| "BLOCKED_BY_TUN_STARTUP_CANCELLED".to_owned())?;

    // Run the engine loop, always tearing the capture down on exit (the guard
    // moves in so any return/panic-unwind rolls back).
    let loop_result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
            let _guard = &guard;
            while !stop.load(Ordering::SeqCst) {
                hb = hb.wrapping_add(1);
                heartbeat.store(hb, Ordering::SeqCst);

                if cfg
                    .forward_gate
                    .as_ref()
                    .is_some_and(|gate| !gate.is_open())
                {
                    // Do not admit captured frames into smoltcp while closed.
                    // Discard a bounded batch without retaining user-space input.
                    let mut discarded = [0u8; 65_536];
                    for _ in 0..64 {
                        if unsafe { libc::read(fd, discarded.as_mut_ptr().cast(), discarded.len()) }
                            <= 0
                        {
                            break;
                        }
                    }
                    tcp_flows.clear();
                    udp_flows.clear();
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                // 1. Drain the fd: learn destination ports, arm listeners, and stage
                //    the frames for smoltcp to consume from the injection queue.
                drain_fd(
                    fd,
                    &mut phy.inject,
                    &mut sockets,
                    &mut tcp_listeners,
                    &mut udp_ports,
                    cfg.max_flows,
                    tcp_flows.len(),
                )?;

                // 2. Poll: smoltcp processes the staged frames (listeners already armed)
                //    and transmits replies to the fd.
                if let Some(gate) = &cfg.forward_gate {
                    let _ =
                        gate.with_open(|| iface.poll(SmolInstant::now(), &mut phy, &mut sockets));
                } else {
                    let _ = iface.poll(SmolInstant::now(), &mut phy, &mut sockets);
                }

                // 3. Promote any listener that caught a SYN into a relayed flow.
                promote_tcp_flows(
                    &mut sockets,
                    &mut tcp_listeners,
                    &mut tcp_flows,
                    &rt,
                    &settings,
                    cfg.max_flows,
                    &mut stats,
                    cfg.forward_gate.as_ref(),
                );

                // 4. Pump established TCP flows (smoltcp <-> localhost bridge <-> relay).
                if let Some(gate) = &cfg.forward_gate {
                    let _ =
                        gate.with_open(|| pump_tcp_flows(&mut sockets, &mut tcp_flows, &mut stats));
                } else {
                    pump_tcp_flows(&mut sockets, &mut tcp_flows, &mut stats);
                }

                // 5. Service UDP: route captured datagrams into per-flow PERSISTENT
                //    MASQUE sessions (off-thread), inject ready replies into smoltcp.
                service_udp(
                    &mut sockets,
                    &udp_ports,
                    &mut udp_flows,
                    &rt,
                    &settings,
                    &udp_tx,
                    cfg.max_flows,
                    &mut stats,
                    cfg.forward_gate.as_ref(),
                );
                if let Some(gate) = &cfg.forward_gate {
                    let _ = gate.with_open(|| {
                        inject_udp_replies(&mut sockets, &udp_ports, &udp_rx, &mut stats)
                    });
                } else {
                    inject_udp_replies(&mut sockets, &udp_ports, &udp_rx, &mut stats);
                }

                // 6. Replenish listener pools and reap idle/closed state ~1Hz.
                replenish_listeners(&mut sockets, &mut tcp_listeners);
                if last_sweep.elapsed() >= Duration::from_secs(1) {
                    last_sweep = Instant::now();
                    reap(&mut udp_flows, Instant::now(), cfg.idle_timeout);
                }

                // 7. Idle a touch if there was no inbound work, to avoid a busy-spin.
                if phy.inject.is_empty() && tcp_flows.is_empty() {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Ok(())
        }));

    // Always tear down, regardless of how the loop exited.
    guard.teardown();
    stop.store(true, Ordering::SeqCst);
    let _ = watchdog.join();

    match loop_result {
        Ok(Ok(())) => {
            stats.clean_teardown = true;
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::Ipv6UdpFlowClosed,
                "wide tun engine stopped cleanly",
                json!({
                    "tcp_flows_opened": stats.tcp_flows_opened,
                    "udp_sessions_opened": stats.udp_sessions_opened,
                    "tcp_egress_bytes": stats.tcp_egress_bytes,
                    "udp_egress_bytes": stats.udp_egress_bytes,
                }),
            );
            Ok(stats)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => {
            Err("BLOCKED_BY_TUN_ENGINE: poll loop panicked (capture rolled back)".to_string())
        }
    }
}

/// Read all currently-available frames off the TUN fd. For each IPv6 TCP/UDP
/// frame, ensure a listener/socket exists for its destination port (so smoltcp
/// does not RST the SYN), then stage the frame for smoltcp to consume.
#[allow(clippy::too_many_arguments)]
fn drain_fd(
    fd: i32,
    inject: &mut VecDeque<Vec<u8>>,
    sockets: &mut SocketSet,
    tcp_listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    udp_ports: &mut HashMap<u16, SocketHandle>,
    max_flows: usize,
    live_flows: usize,
) -> Result<(), String> {
    // Cap the batch so a flood cannot starve the rest of the loop.
    for _ in 0..256 {
        let mut buf = vec![0u8; TUN_MTU];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
            ) {
                break;
            }
            return Err("BLOCKED_BY_TUN_READ: capture descriptor failed".to_owned());
        }
        if n == 0 {
            return Err("BLOCKED_BY_TUN_READ: capture descriptor closed".to_owned());
        }
        buf.truncate(n as usize);
        if let Ok(pkt) = decode_packet(&buf) {
            if pkt.is_ipv6() {
                let port = pkt.dst_port();
                match pkt {
                    DecodedPacket::Tcp(_) => {
                        // Only arm new listeners while there is flow headroom; at
                        // capacity smoltcp will RST the SYN (fail-closed).
                        if live_flows + tcp_flows_pending(tcp_listeners)
                            < max_flows.saturating_mul(2)
                        {
                            ensure_tcp_listeners(sockets, tcp_listeners, port);
                        }
                    }
                    DecodedPacket::Udp(_) => ensure_udp_socket(sockets, udp_ports, port),
                }
            }
        }
        inject.push_back(buf);
    }
    Ok(())
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
    if udp_ports.contains_key(&port) {
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
    stats: &mut TunEngineStats,
    gate: Option<&super::forward_gate::ForwardGate>,
) {
    promote_tcp_flows_with(
        sockets,
        tcp_listeners,
        tcp_flows,
        max_flows,
        stats,
        gate,
        &mut |orig_dst| open_relay_bridge(rt, settings, orig_dst, gate),
    );
}

/// `promote_tcp_flows`, with `open_bridge` opening the relay bridge of a
/// promoted connection to its original destination.
fn promote_tcp_flows_with(
    sockets: &mut SocketSet,
    tcp_listeners: &mut HashMap<u16, Vec<SocketHandle>>,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    max_flows: usize,
    stats: &mut TunEngineStats,
    gate: Option<&super::forward_gate::ForwardGate>,
    open_bridge: &mut dyn FnMut(IpEndpoint) -> Result<std::net::TcpStream, String>,
) {
    if gate.is_some_and(|gate| !gate.is_open()) {
        return;
    }
    // Promote the instant a listener leaves Listen — i.e. it caught a SYN and now
    // has a recorded (orig_dst, src) tuple, even if still mid-handshake
    // (SynReceived). Waiting for may_send()/Established would race
    // replenish_listeners, which evicts non-Listen sockets from the pool and would
    // orphan the connection (established + ACKing but never relayed).
    //
    // A RST in SYN-RECEIVED (an app that gave up its connect before the
    // SYN-ACK arrived, such as a happy-eyeballs loser) returns a smoltcp 0.12
    // socket to LISTEN with its tuple cleared, where it accepts the port's
    // next SYN for ANY destination. Such a socket no longer carries the
    // connection its flow was promoted for: end that flow (dropping its
    // bridge ends its relay work) and return the socket to its port's
    // listeners, so a connection it has accepted since is promoted below, to
    // its own destination. Left in the flow, it would carry that next
    // connection's bytes to the abandoned destination and its replies back,
    // and a socket back in LISTEN is never removed (TcpStreamPump::removable).
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
        match open_bridge(orig_dst) {
            Ok(bridge) => {
                stats.tcp_flows_opened += 1;
                runtime_jsonl::emit(
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
                    },
                );
            }
            Err(e) => {
                // Relay bridge could not be opened: drop the flow (fail-closed).
                runtime_jsonl::emit(
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

/// Register the nonblocking listener before returning a bridge or spawning work.
/// Registration errors must reach the flow owner, rather than panic in a
/// detached relay task after that owner has already reported an open bridge.
fn open_localhost_bridge(
    rt: &tokio::runtime::Runtime,
) -> Result<(std::net::TcpStream, tokio::net::TcpListener), String> {
    let listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).map_err(|e| format!("bind {e}"))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| format!("listener nonblocking {e}"))?;
    let address = listener.local_addr().map_err(|e| e.to_string())?;
    let listener = {
        let _entered = rt.enter();
        tokio::net::TcpListener::from_std(listener).map_err(|e| format!("register listener {e}"))?
    };
    let bridge = std::net::TcpStream::connect(address).map_err(|e| format!("connect {e}"))?;
    bridge.set_nonblocking(true).map_err(|e| e.to_string())?;
    Ok((bridge, listener))
}

/// Open a localhost bridge and spawn the relay tunnel carrying it to `orig_dst`.
fn open_relay_bridge(
    rt: &tokio::runtime::Runtime,
    settings: &Arc<RelaySettings>,
    orig_dst: IpEndpoint,
    gate: Option<&super::forward_gate::ForwardGate>,
) -> Result<std::net::TcpStream, String> {
    let (bridge, listener) = open_localhost_bridge(rt)?;
    let settings = settings.clone();
    let host = orig_dst.addr.to_string();
    let port = orig_dst.port;
    let gate = gate.cloned();
    rt.spawn(async move {
        let _ = super::forward_gate::run_optional(gate.as_ref(), async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ =
                    crate::relay::run_relay_tunnel(stream, &settings, host, port, None, None, None)
                        .await;
            }
        })
        .await;
    });
    Ok(bridge)
}

/// Pump bytes between each smoltcp TCP socket and its localhost relay bridge.
fn pump_tcp_flows(
    sockets: &mut SocketSet,
    tcp_flows: &mut HashMap<SocketHandle, TcpFlow>,
    stats: &mut TunEngineStats,
) {
    let mut closed: Vec<SocketHandle> = Vec::new();
    for flow in tcp_flows.values_mut() {
        let s = sockets.get_mut::<tcp::Socket>(flow.handle);
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
            Err(_) => s.abort(),
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
    stats: &mut TunEngineStats,
    gate: Option<&super::forward_gate::ForwardGate>,
) {
    if gate.is_some_and(|gate| !gate.is_open()) {
        return;
    }
    for (&port, &handle) in udp_ports.iter() {
        loop {
            if gate.is_some_and(|gate| !gate.is_open()) {
                return;
            }
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
            let payload =
                match send_to_existing_udp_flow(udp_flows, &key, payload, Instant::now()) {
                    ExistingUdpFlowSend::Queued
                    | ExistingUdpFlowSend::QueueFull
                    | ExistingUdpFlowSend::RetryCooldown => continue,
                    ExistingUdpFlowSend::Missing(payload)
                    | ExistingUdpFlowSend::Closed(payload) => payload,
                };
            // New flow: at capacity -> drop (fail-closed), never native.
            if udp_flows.len() >= max_flows {
                continue;
            }
            // Spawn ONE persistent MASQUE CONNECT-UDP session for this flow. A
            // forwarder tags each response with this flow's (src, dst) and hands it
            // to the poll loop for smoltcp injection.
            let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
            let (in_tx, mut in_rx) = tokio::sync::mpsc::channel::<crate::socks5::UdpPacket>(256);
            let reply_tx = udp_tx.clone();
            let reply_gate = gate.cloned();
            let packet_gate = reply_gate.clone();
            rt.spawn(async move {
                let _ = super::forward_gate::run_optional(reply_gate.as_ref(), async move {
                    while let Some(pkt) = in_rx.recv().await {
                        if packet_gate.as_ref().is_some_and(|gate| !gate.is_open()) {
                            break;
                        }
                        match reply_tx.try_send(UdpReply {
                            port,
                            src,
                            orig_dst: orig_dst_ip,
                            resp: pkt.payload,
                        }) {
                            Ok(()) | Err(std::sync::mpsc::TrySendError::Full(_)) => {}
                            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                        }
                    }
                })
                .await;
            });
            let settings = settings.clone();
            let host = orig_dst_ip.to_string();
            let relay_gate = gate.cloned();
            rt.spawn(async move {
                let _ = super::forward_gate::run_optional(relay_gate.as_ref(), async move {
                    // Fail-closed: a failed/ended session just stops; no native egress.
                    let _ = crate::relay::run_relay_udp_flow(&settings, &host, port, out_rx, in_tx)
                        .await;
                })
                .await;
            });
            let _ = out_tx.try_send(payload);
            udp_flows.insert(key, UdpFlow::new(out_tx, Instant::now()));
            stats.udp_sessions_opened += 1;
            runtime_jsonl::emit(
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
    sockets: &mut SocketSet,
    udp_ports: &HashMap<u16, SocketHandle>,
    udp_rx: &std::sync::mpsc::Receiver<UdpReply>,
    stats: &mut TunEngineStats,
) {
    while let Ok(reply) = udp_rx.try_recv() {
        let Some(&handle) = udp_ports.get(&reply.port) else {
            continue;
        };
        let s = sockets.get_mut::<udp::Socket>(handle);
        let meta = udp::UdpMetadata {
            endpoint: reply.src,
            local_address: Some(reply.orig_dst),
            meta: PacketMeta::default(),
        };
        if s.send_slice(&reply.resp, meta).is_ok() {
            stats.udp_egress_bytes += reply.resp.len() as u64;
            runtime_jsonl::emit(
                "info",
                RuntimeEventCode::Ipv6UdpResponseDelivered,
                "wide tun engine ipv6 udp response delivered (bidirectional)",
                json!({ "src": reply.src.to_string(), "response_len": reply.resp.len() }),
            );
        }
    }
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
                matches!(
                    sockets.get_mut::<tcp::Socket>(h).state(),
                    tcp::State::Listen
                )
            });
        }
        ensure_tcp_listeners(sockets, tcp_listeners, port);
    }
}

/// Reap idle or ended UDP flows after their opening cooldown. Dropping a `UdpFlow`
/// drops its `outbound_tx`, which closes the session's `outbound_rx` and ends the
/// persistent MASQUE QUIC session cleanly.
fn reap(
    udp_flows: &mut HashMap<(IpEndpoint, IpEndpoint), UdpFlow>,
    now: Instant,
    idle_timeout: Duration,
) {
    udp_flows.retain(|_, flow| {
        if flow.outbound_tx.is_closed() {
            now < flow.next_open_at
        } else {
            now.duration_since(flow.last_active) < idle_timeout
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn udp_recovery_key() -> (IpEndpoint, IpEndpoint) {
        (
            IpEndpoint::new(
                IpAddress::Ipv6(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1)),
                5000,
            ),
            IpEndpoint::new(
                IpAddress::Ipv6(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                443,
            ),
        )
    }

    #[test]
    fn udp_closed_flow_recovery_continuous_traffic_bounds_retries_without_replay() {
        let key = udp_recovery_key();
        let start = Instant::now();
        let mut flows = HashMap::new();
        let mut openings = Vec::new();
        let mut healthy_receiver = None;
        // The first three relay receivers end immediately. A fourth survives
        // while the application sends every 10 ms, without an idle interval.
        for tick in 0..=310 {
            let now = start + Duration::from_millis(tick * 10);
            reap(&mut flows, now, Duration::from_secs(30));
            let payload = (tick as u32).to_be_bytes().to_vec();
            match send_to_existing_udp_flow(&mut flows, &key, payload.clone(), now) {
                ExistingUdpFlowSend::Missing(first) | ExistingUdpFlowSend::Closed(first) => {
                    assert_eq!(
                        first, payload,
                        "only the current unaccepted datagram retries"
                    );
                    openings.push(now);
                    let (tx, mut rx) = tokio::sync::mpsc::channel(1);
                    tx.try_send(first.clone()).unwrap();
                    flows.insert(key, UdpFlow::new(tx, now));
                    if openings.len() <= 3 {
                        // This first payload has already committed to that
                        // receiver; it is never retained for a later attempt.
                        drop(rx);
                    } else {
                        assert_eq!(rx.try_recv().unwrap(), payload);
                        assert!(rx.try_recv().is_err(), "no historical datagrams replayed");
                        healthy_receiver = Some(rx);
                    }
                }
                ExistingUdpFlowSend::RetryCooldown => {
                    let last_open = *openings.last().unwrap();
                    assert_eq!(flows[&key].last_active, last_open);
                    assert_eq!(
                        flows[&key].next_open_at,
                        last_open + UDP_FLOW_RECONNECT_COOLDOWN
                    );
                    assert!(healthy_receiver.is_none());
                }
                ExistingUdpFlowSend::Queued => {
                    assert_eq!(
                        healthy_receiver.as_mut().unwrap().try_recv().unwrap(),
                        payload
                    );
                }
                ExistingUdpFlowSend::QueueFull => panic!("healthy receiver drains every datagram"),
            }
        }
        assert_eq!(openings.len(), 4);
        for (index, opened) in openings.iter().enumerate() {
            assert_eq!(*opened, start + UDP_FLOW_RECONNECT_COOLDOWN * index as u32);
        }
        assert!(healthy_receiver.is_some());
    }

    #[test]
    fn udp_closed_flow_recovery_full_live_queue_keeps_one_session() {
        let key = udp_recovery_key();
        let start = Instant::now();
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let original = tx.clone();
        let mut flows = HashMap::from([(key, UdpFlow::new(tx, start))]);
        assert_eq!(
            send_to_existing_udp_flow(&mut flows, &key, vec![1], start),
            ExistingUdpFlowSend::Queued
        );
        for seconds in 1..64 {
            let now = start + Duration::from_secs(seconds);
            assert_eq!(
                send_to_existing_udp_flow(&mut flows, &key, vec![2], now),
                ExistingUdpFlowSend::QueueFull
            );
            reap(&mut flows, now, Duration::from_secs(30));
            assert_eq!(flows.len(), 1);
            assert!(flows[&key].outbound_tx.same_channel(&original));
        }
        assert_eq!(rx.try_recv().unwrap(), vec![1]);
        assert!(rx.try_recv().is_err(), "full-queue datagrams stay dropped");
    }

    #[test]
    fn udp_closed_flow_recovery_receiver_closes_after_sweep_at_cooldown_boundary() {
        let key = udp_recovery_key();
        let start = Instant::now();
        let (tx, rx) = tokio::sync::mpsc::channel(1);
        let mut flows = HashMap::from([(key, UdpFlow::new(tx, start))]);
        reap(&mut flows, start, Duration::from_secs(30));
        drop(rx);
        let before_retry = start + UDP_FLOW_RECONNECT_COOLDOWN - Duration::from_nanos(1);
        // Even an idle policy shorter than the cooldown cannot bypass it.
        reap(&mut flows, before_retry, Duration::ZERO);
        assert_eq!(
            send_to_existing_udp_flow(&mut flows, &key, vec![1], before_retry),
            ExistingUdpFlowSend::RetryCooldown
        );
        assert_eq!(flows[&key].last_active, start);
        assert_eq!(
            send_to_existing_udp_flow(
                &mut flows,
                &key,
                vec![2],
                start + UDP_FLOW_RECONNECT_COOLDOWN
            ),
            ExistingUdpFlowSend::Closed(vec![2])
        );
        assert!(flows.is_empty());
    }

    #[test]
    fn localhost_bridge_exchanges_bytes_and_half_close_without_blocking_tokio() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        // Call the production boundary outside any entered Tokio context,
        // exactly as the synchronous TUN worker does.
        let (bridge, listener) = open_localhost_bridge(&runtime).unwrap();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(3), async {
                let mut client = tokio::net::TcpStream::from_std(bridge).unwrap();
                let (mut accepted, peer) = listener.accept().await.unwrap();
                assert!(peer.ip().is_loopback());
                client.write_all(b"captured request").await.unwrap();
                client.shutdown().await.unwrap();
                let mut request = Vec::new();
                accepted.read_to_end(&mut request).await.unwrap();
                assert_eq!(request, b"captured request");
                accepted.write_all(b"relay response").await.unwrap();
                accepted.shutdown().await.unwrap();
                let mut response = Vec::new();
                client.read_to_end(&mut response).await.unwrap();
                assert_eq!(response, b"relay response");
                // A second accept has no queued connection and must yield,
                // keeping the same runtime's timer responsive.
                assert!(
                    tokio::time::timeout(Duration::from_millis(10), listener.accept())
                        .await
                        .is_err()
                );
            })
            .await
            .expect("bridge I/O must not block the Tokio runtime");
        });
    }

    #[test]
    fn capture_descriptor_errors_are_terminal_but_idle_reads_are_not() {
        use std::os::fd::AsRawFd;
        let (read, write) = std::os::unix::net::UnixStream::pair().unwrap();
        read.set_nonblocking(true).unwrap();
        let mut inject = VecDeque::new();
        let mut sockets = SocketSet::new(vec![]);
        let mut tcp = HashMap::new();
        let mut udp = HashMap::new();
        assert!(drain_fd(
            read.as_raw_fd(),
            &mut inject,
            &mut sockets,
            &mut tcp,
            &mut udp,
            1,
            0
        )
        .is_ok());
        drop(write);
        assert!(drain_fd(
            read.as_raw_fd(),
            &mut inject,
            &mut sockets,
            &mut tcp,
            &mut udp,
            1,
            0
        )
        .is_err());
        assert!(drain_fd(-1, &mut inject, &mut sockets, &mut tcp, &mut udp, 1, 0).is_err());
        assert!(inject.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires isolated Linux network namespace, /dev/net/tun and NET_ADMIN"]
    async fn native_capture_worker_readiness_and_owned_teardown() {
        let mut cfg = TunEngineConfig::new(RelaySettings::default());
        cfg.ifname = "aegis-ready0".to_owned();
        let mut workers = crate::wide_workers::WideWorkers::new();
        let (tx, rx) = tokio::sync::oneshot::channel();
        workers
            .start("tun-native", Duration::from_secs(5), move |stop, ready| {
                tx.send(run_tun_engine(cfg, stop, ready)).unwrap();
            })
            .await
            .unwrap();
        let routes = Command::new("ip")
            .args(["-6", "route", "show", "dev", "aegis-ready0"])
            .output()
            .unwrap();
        let routes = String::from_utf8(routes.stdout).unwrap();
        assert!(routes.lines().any(|s| s.starts_with("::/1 ")));
        assert!(routes.lines().any(|s| s.starts_with("8000::/1 ")));
        assert!(
            TunDevice::open("aegis-ready0").is_err(),
            "second worker cannot attach to the first one's TUN"
        );
        drop(workers);
        let stats = tokio::time::timeout(Duration::from_secs(3), rx)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(stats.clean_teardown);
        assert!(!Command::new("ip")
            .args(["link", "show", "dev", "aegis-ready0"])
            .status()
            .unwrap()
            .success());
    }

    /// An in-memory IP device for the promotion tests: it serves staged
    /// frames and records every frame smoltcp transmits.
    #[derive(Default)]
    struct FrameDevice {
        rx: VecDeque<Vec<u8>>,
        tx: Vec<Vec<u8>>,
    }
    struct FrameRx(Vec<u8>);
    struct FrameTx<'a>(&'a mut Vec<Vec<u8>>);
    impl Device for FrameDevice {
        type RxToken<'a>
            = FrameRx
        where
            Self: 'a;
        type TxToken<'a>
            = FrameTx<'a>
        where
            Self: 'a;
        fn receive(&mut self, _: SmolInstant) -> Option<(FrameRx, FrameTx<'_>)> {
            let frame = self.rx.pop_front()?;
            Some((FrameRx(frame), FrameTx(&mut self.tx)))
        }
        fn transmit(&mut self, _: SmolInstant) -> Option<FrameTx<'_>> {
            Some(FrameTx(&mut self.tx))
        }
        fn capabilities(&self) -> DeviceCapabilities {
            let mut caps = DeviceCapabilities::default();
            caps.medium = Medium::Ip;
            caps.max_transmission_unit = TUN_MTU;
            caps.checksum = smoltcp::phy::ChecksumCapabilities::ignored();
            caps
        }
    }
    impl RxToken for FrameRx {
        fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
            f(&self.0)
        }
    }
    impl TxToken for FrameTx<'_> {
        fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
            let mut frame = vec![0u8; len];
            let result = f(&mut frame);
            self.0.push(frame);
            result
        }
    }

    const PROMOTION_APP: Ipv6Address = Ipv6Address::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 0x99);

    /// An IPv6 TCP segment from the app's `src_port` to `dst`:443.
    fn app_segment(
        src_port: u16,
        dst: Ipv6Address,
        control: smoltcp::wire::TcpControl,
        seq: u32,
        ack: Option<u32>,
        payload: &[u8],
    ) -> Vec<u8> {
        use smoltcp::wire::{IpProtocol, Ipv6Packet, Ipv6Repr, TcpPacket, TcpRepr, TcpSeqNumber};
        let tcp = TcpRepr {
            src_port,
            dst_port: 443,
            control,
            seq_number: TcpSeqNumber(seq as i32),
            ack_number: ack.map(|ack| TcpSeqNumber(ack as i32)),
            window_len: 64240,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload,
        };
        let ip = Ipv6Repr {
            src_addr: PROMOTION_APP,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let mut frame = vec![0u8; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(&mut Ipv6Packet::new_unchecked(&mut frame));
        let (_, segment) = frame.split_at_mut(ip.buffer_len());
        tcp.emit(
            &mut TcpPacket::new_unchecked(segment),
            &IpAddress::Ipv6(PROMOTION_APP),
            &IpAddress::Ipv6(dst),
            &smoltcp::phy::ChecksumCapabilities::ignored(),
        );
        frame
    }

    /// (SYN, ACK, sequence number) of every segment smoltcp sent to the
    /// app's `app_port` since the last call.
    fn sent_to_app(dev: &mut FrameDevice, app_port: u16) -> Vec<(bool, bool, u32)> {
        use smoltcp::wire::{Ipv6Packet, TcpPacket};
        dev.tx
            .drain(..)
            .filter_map(|frame| {
                let ip = Ipv6Packet::new_checked(&frame[..]).ok()?;
                let tcp = TcpPacket::new_checked(ip.payload()).ok()?;
                (tcp.dst_port() == app_port)
                    .then(|| (tcp.syn(), tcp.ack(), tcp.seq_number().0 as u32))
            })
            .collect()
    }

    /// Every byte readable now from a bridge's far end (none at EOF).
    fn readable_now(stream: &mut std::net::TcpStream) -> Vec<u8> {
        use std::io::Read;
        let mut bytes = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            match stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => bytes.extend_from_slice(&buf[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("bridge read: {error}"),
            }
        }
        bytes
    }

    /// The engine loop's TCP half on an any-ip interface, port 443: arm the
    /// listeners (drain_fd), poll, promote, pump and replenish. Every relay
    /// bridge it opens is a localhost pair whose far end is recorded with
    /// the destination it was opened for.
    struct Promotion {
        iface: Interface,
        dev: FrameDevice,
        sockets: SocketSet<'static>,
        listeners: HashMap<u16, Vec<SocketHandle>>,
        flows: HashMap<SocketHandle, TcpFlow>,
        stats: TunEngineStats,
        now_ms: i64,
        opened: Vec<(IpEndpoint, std::net::TcpStream)>,
    }

    impl Promotion {
        fn new() -> Self {
            let anchor = Ipv6Address::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 1);
            let mut dev = FrameDevice::default();
            let mut config = Config::new(HardwareAddress::Ip);
            config.random_seed = 0xae61_5c10;
            let mut iface = Interface::new(config, &mut dev, SmolInstant::from_millis(0));
            iface.set_any_ip(true);
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(anchor), 128));
            });
            let _ = iface.routes_mut().add_default_ipv6_route(anchor);
            Self {
                iface,
                dev,
                sockets: SocketSet::new(vec![]),
                listeners: HashMap::new(),
                flows: HashMap::new(),
                stats: TunEngineStats::default(),
                now_ms: 0,
                opened: Vec::new(),
            }
        }

        fn step(&mut self) {
            self.now_ms += 10;
            ensure_tcp_listeners(&mut self.sockets, &mut self.listeners, 443);
            let _ = self.iface.poll(
                SmolInstant::from_millis(self.now_ms),
                &mut self.dev,
                &mut self.sockets,
            );
            let opened = &mut self.opened;
            promote_tcp_flows_with(
                &mut self.sockets,
                &mut self.listeners,
                &mut self.flows,
                DEFAULT_MAX_FLOWS,
                &mut self.stats,
                None,
                &mut |orig_dst| {
                    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
                        .map_err(|error| error.to_string())?;
                    let near = std::net::TcpStream::connect(listener.local_addr().unwrap())
                        .map_err(|error| error.to_string())?;
                    let (far, _) = listener.accept().map_err(|error| error.to_string())?;
                    near.set_nonblocking(true).unwrap();
                    far.set_nonblocking(true).unwrap();
                    opened.push((orig_dst, far));
                    Ok(near)
                },
            );
            pump_tcp_flows(&mut self.sockets, &mut self.flows, &mut self.stats);
            replenish_listeners(&mut self.sockets, &mut self.listeners);
        }
    }

    /// The rc=35 class on the Linux IPv6 TUN path (the shared engine's
    /// 8755aff5, same smoltcp 0.12 mechanism): an app answered with a SYN-ACK
    /// resets its connect at the SYN-ACK's ack number (a happy-eyeballs
    /// loser, or the kernel's answer to a SYN-ACK it no longer expects),
    /// which returns the promoted socket to LISTEN with its tuple cleared.
    /// The port's next SYN, to another destination, must get its own relay
    /// bridge, and the abandoned destination must receive none of its bytes.
    /// With a gap (one engine pass between them) or back to back (one poll).
    fn next_syn_after_a_reset_syn_received(back_to_back: bool) {
        use smoltcp::wire::TcpControl;
        const ISN: u32 = 7_000;
        let a = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);
        let b = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 8);
        let mut engine = Promotion::new();

        engine
            .dev
            .rx
            .push_back(app_segment(41_000, a, TcpControl::Syn, ISN, None, &[]));
        engine.step();
        assert!(
            sent_to_app(&mut engine.dev, 41_000)
                .iter()
                .any(|&(syn, ack, _)| syn && ack),
            "the SYN to A is answered"
        );
        engine.dev.rx.push_back(app_segment(
            41_000,
            a,
            TcpControl::Rst,
            ISN.wrapping_add(1),
            None,
            &[],
        ));
        let mut flows_after_reset = None;
        if !back_to_back {
            engine.step();
            flows_after_reset = Some(engine.flows.len());
        }
        engine
            .dev
            .rx
            .push_back(app_segment(41_001, b, TcpControl::Syn, ISN, None, &[]));
        engine.step();
        let (_, _, server_isn) = sent_to_app(&mut engine.dev, 41_001)
            .into_iter()
            .find(|&(syn, ack, _)| syn && ack)
            .expect("the SYN to B is answered");
        engine.dev.rx.push_back(app_segment(
            41_001,
            b,
            TcpControl::Psh,
            ISN.wrapping_add(1),
            Some(server_isn.wrapping_add(1)),
            b"hello",
        ));
        let mut relayed = Vec::new();
        for _ in 0..50 {
            engine.step();
            if let Some((_, far)) = engine.opened.get_mut(1) {
                relayed.extend(readable_now(far));
            }
            if relayed.len() >= 5 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }

        let to_a = readable_now(&mut engine.opened[0].1);
        assert!(
            to_a.is_empty(),
            "the abandoned destination A received {:?}",
            String::from_utf8_lossy(&to_a)
        );
        let destinations: Vec<IpAddress> = engine.opened.iter().map(|(dst, _)| dst.addr).collect();
        assert_eq!(
            destinations,
            [IpAddress::Ipv6(a), IpAddress::Ipv6(b)],
            "B's connection gets its own relay bridge"
        );
        assert!(engine.opened.iter().all(|(dst, _)| dst.port == 443));
        assert_eq!(relayed, b"hello", "B's bytes reach B's bridge");
        assert_eq!(engine.stats.tcp_flows_opened, 2);
        if let Some(flows) = flows_after_reset {
            assert_eq!(flows, 0, "the reset connection's flow ends at once");
        }
        assert_eq!(engine.flows.len(), 1, "B's flow is the only flow");
    }

    #[test]
    fn rst_in_syn_received_never_splices_the_next_syn_into_the_old_flow() {
        next_syn_after_a_reset_syn_received(false);
    }

    #[test]
    fn rst_and_the_next_syn_back_to_back_never_splice_into_the_old_flow() {
        next_syn_after_a_reset_syn_received(true);
    }

    #[test]
    fn config_defaults_are_failclosed_safe() {
        let cfg = TunEngineConfig::new(RelaySettings::default());
        assert_eq!(cfg.ifname, "aegis-tun0");
        assert_eq!(cfg.max_flows, DEFAULT_MAX_FLOWS);
        // Anchor must be an AEGIS ULA, never a global address.
        assert_eq!(
            cfg.anchor,
            Ipv6Address::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 1)
        );
        assert!(cfg.relay_excludes.is_empty());
    }

    #[test]
    fn parse_default_gw_dev_extracts_gateway_and_device() {
        let text = "default via fe80::1 dev eth0 proto ra metric 1024 pref medium\n";
        assert_eq!(
            parse_default_gw_dev(text),
            Some(("fe80::1".to_string(), "eth0".to_string()))
        );
    }

    #[test]
    fn parse_default_gw_dev_none_when_no_default() {
        let text = "fd00:ae61::/64 dev aegis-tun0 metric 100\n";
        assert_eq!(parse_default_gw_dev(text), None);
    }

    #[test]
    fn parse_default_gw_dev_handles_reordered_tokens() {
        // dev before via still parses.
        let text = "default dev eth0 via 2001:db8::1 metric 100\n";
        assert_eq!(
            parse_default_gw_dev(text),
            Some(("2001:db8::1".to_string(), "eth0".to_string()))
        );
    }

    /// The core production mechanism, proven WITHOUT root or a real TUN: with
    /// `set_any_ip(true)` + a default route via the OWNED anchor, a smoltcp
    /// interface accepts a TCP SYN to an ARBITRARY (unowned) IPv6 destination, and
    /// the listening socket recovers that original destination via
    /// `local_endpoint()`. This is exactly what lets the engine relay any IPv6
    /// target instead of a single fixed `/128`.
    #[test]
    fn any_ip_accepts_arbitrary_dst_and_recovers_original_destination() {
        use smoltcp::iface::{Config, Interface, SocketSet};
        use smoltcp::phy::{
            ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken, TxToken,
        };
        use smoltcp::socket::tcp;
        use smoltcp::time::Instant as SmolInstant;
        use smoltcp::wire::{
            HardwareAddress, IpAddress, IpCidr, IpProtocol, Ipv6Address, Ipv6Packet, Ipv6Repr,
            TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
        };
        use std::collections::VecDeque;

        // Minimal in-memory IP device: serves one staged frame, sinks TX.
        struct Mock {
            rx: VecDeque<Vec<u8>>,
        }
        struct MRx {
            buf: Vec<u8>,
        }
        struct MTx;
        impl Device for Mock {
            type RxToken<'a>
                = MRx
            where
                Self: 'a;
            type TxToken<'a>
                = MTx
            where
                Self: 'a;
            fn receive(&mut self, _t: SmolInstant) -> Option<(MRx, MTx)> {
                self.rx.pop_front().map(|buf| (MRx { buf }, MTx))
            }
            fn transmit(&mut self, _t: SmolInstant) -> Option<MTx> {
                Some(MTx)
            }
            fn capabilities(&self) -> DeviceCapabilities {
                let mut c = DeviceCapabilities::default();
                c.medium = Medium::Ip;
                c.max_transmission_unit = 1500;
                c.checksum = ChecksumCapabilities::ignored();
                c
            }
        }
        impl RxToken for MRx {
            fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
                f(&self.buf)
            }
        }
        impl TxToken for MTx {
            fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
                let mut b = vec![0u8; len];
                f(&mut b)
            }
        }

        let anchor = Ipv6Address::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 1);
        let src = Ipv6Address::new(0xfd00, 0xae61, 0, 0, 0, 0, 0, 0x99);
        // Arbitrary destination NOT owned by the interface — the whole point.
        let dst = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xdead, 0xbeef);

        // Build a bare IPv6 TCP SYN to (dst, 80).
        let tcp_repr = TcpRepr {
            src_port: 40001,
            dst_port: 80,
            control: TcpControl::Syn,
            seq_number: TcpSeqNumber(1000),
            ack_number: None,
            window_len: 64240,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None, None, None],
            timestamp: None,
            payload: &[],
        };
        let ip_repr = Ipv6Repr {
            src_addr: src,
            dst_addr: dst,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        };
        let mut frame = vec![0u8; ip_repr.buffer_len() + ip_repr.payload_len];
        {
            let mut ippkt = Ipv6Packet::new_unchecked(&mut frame);
            ip_repr.emit(&mut ippkt);
        }
        {
            let (hdr, payload) = frame.split_at_mut(ip_repr.buffer_len());
            let _ = hdr;
            let mut tcppkt = TcpPacket::new_unchecked(payload);
            tcp_repr.emit(
                &mut tcppkt,
                &IpAddress::Ipv6(src),
                &IpAddress::Ipv6(dst),
                &ChecksumCapabilities::ignored(),
            );
        }

        let mut dev = Mock {
            rx: VecDeque::from(vec![frame]),
        };
        let mut config = Config::new(HardwareAddress::Ip);
        config.random_seed = 1;
        let mut iface = Interface::new(config, &mut dev, SmolInstant::now());
        iface.set_any_ip(true);
        iface.update_ip_addrs(|a| {
            let _ = a.push(IpCidr::new(IpAddress::Ipv6(anchor), 128));
        });
        // Default route via the OWNED anchor — the key that arms any-ip accept.
        let _ = iface.routes_mut().add_default_ipv6_route(anchor);

        let mut sockets = SocketSet::new(vec![]);
        let sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0u8; 4096]),
            tcp::SocketBuffer::new(vec![0u8; 4096]),
        );
        let h = sockets.add(sock);
        // Port-only listen (addr unspecified) so it accepts any destination.
        sockets.get_mut::<tcp::Socket>(h).listen(80).unwrap();

        for _ in 0..4 {
            let _ = iface.poll(SmolInstant::now(), &mut dev, &mut sockets);
        }

        let s = sockets.get_mut::<tcp::Socket>(h);
        assert!(
            s.is_active(),
            "any-ip SYN to an unowned destination must be accepted"
        );
        let local = s
            .local_endpoint()
            .expect("accepted flow must record its original destination tuple");
        assert_eq!(
            local.addr,
            IpAddress::Ipv6(dst),
            "recovered original dst must equal the arbitrary captured destination"
        );
        assert_eq!(local.port, 80);
    }
}
