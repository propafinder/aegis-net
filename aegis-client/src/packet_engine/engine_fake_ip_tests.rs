//! The engine's fake-IP answers through raw packets: a DNS A query to the
//! tunnel's resolver anchor, then a TCP connect to the answered address,
//! carried by relay services that record the host of each flow and answer
//! every read with it.
//!
//! B-06 build 37 endurance (2026-10-28): 34 of 121 HTTP probes connected to
//! an answered address 60.00 to 62.6 s after its answer (the system resolver
//! still served it) and got the engine's SYN-ACK and then a reset: the engine
//! had forgotten the address at 60 s. A session rebuild started a new map
//! whose first answers were the very addresses caches still held.
use super::*;
use crate::relay_runtime_types::{ConnectTarget, UdpPacket};
use aegis_client::packet_engine::services::{EngineEvent, EventSink, RelayWork};
use std::{
    net::Ipv4Addr,
    sync::Mutex,
    thread::{self, JoinHandle},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::mpsc,
};

const APP: [u8; 4] = [198, 19, 255, 1];
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;
const ISN: u32 = 7_000;

/// The engine's packet device: what the app sends, and what the engine sent.
#[derive(Clone, Default)]
struct Wire {
    to_engine: Arc<Mutex<VecDeque<Vec<u8>>>>,
    from_engine: Arc<Mutex<VecDeque<Vec<u8>>>>,
}
impl PacketIo for Wire {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        Ok(self.to_engine.lock().unwrap().pop_front())
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.from_engine.lock().unwrap().push_back(packet.to_vec());
        Ok(())
    }
}

/// Relay services that record each TCP flow's host and answer every read
/// with that host.
#[derive(Default)]
struct Hosts {
    hosts: Mutex<Vec<String>>,
}
impl EventSink for Hosts {
    fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
}
impl RelayServices for Hosts {
    fn tcp<'a>(
        &'a self,
        mut local: TcpStream,
        _: &'a RelaySettings,
        host: String,
        _: u16,
    ) -> RelayWork<'a, ()> {
        self.hosts.lock().unwrap().push(host.clone());
        Box::pin(async move {
            let mut buf = [0u8; 256];
            loop {
                if local.read(&mut buf).await? == 0 {
                    return Ok(());
                }
                local.write_all(host.as_bytes()).await?;
            }
        })
    }
    fn udp_once<'a>(
        &'a self,
        _: &'a RelaySettings,
        _: ConnectTarget,
        _: &'a [u8],
    ) -> RelayWork<'a, Vec<u8>> {
        Box::pin(std::future::pending())
    }
    fn udp_flow<'a>(
        &'a self,
        _: &'a RelaySettings,
        _: &'a str,
        _: u16,
        out: mpsc::Receiver<Vec<u8>>,
        incoming: mpsc::Sender<UdpPacket>,
    ) -> RelayWork<'a, ()> {
        Box::pin(async move {
            let _held = (out, incoming);
            std::future::pending().await
        })
    }
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        for pair in part.chunks(2) {
            sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 packet from the app to `dst` carrying `l4` (protocol `proto`),
/// with its header and transport checksums (at `sum_at` within `l4`).
fn ipv4(dst: [u8; 4], proto: u8, mut l4: Vec<u8>, sum_at: usize) -> Vec<u8> {
    let length = u16::try_from(l4.len()).unwrap();
    let pseudo = [&APP[..], &dst[..], &[0, proto], &length.to_be_bytes()].concat();
    let sum = checksum(&[&pseudo, &l4]);
    l4[sum_at..sum_at + 2].copy_from_slice(&sum.to_be_bytes());
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(20 + length).to_be_bytes());
    p[6] = 0x40;
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&APP);
    p[16..20].copy_from_slice(&dst);
    let header = checksum(&[&p]);
    p[10..12].copy_from_slice(&header.to_be_bytes());
    p.extend_from_slice(&l4);
    p
}

fn tcp4(dst: Ipv4Addr, sport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&443u16.to_be_bytes());
    t[4..8].copy_from_slice(&seq.to_be_bytes());
    t[8..12].copy_from_slice(&ack.to_be_bytes());
    t[12] = 0x50;
    t[13] = flags;
    t[14..16].copy_from_slice(&0xffffu16.to_be_bytes());
    t.extend_from_slice(payload);
    ipv4(dst.octets(), 6, t, 16)
}

/// A UDP A query for `name` from the app's `sport` to the resolver anchor.
fn a_query(sport: u16, id: u16, name: &str) -> Vec<u8> {
    let mut dns = id.to_be_bytes().to_vec();
    dns.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        dns.push(u8::try_from(label.len()).unwrap());
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0, 0, 1, 0, 1]);
    let mut u = vec![0u8; 8];
    u[0..2].copy_from_slice(&sport.to_be_bytes());
    u[2..4].copy_from_slice(&53u16.to_be_bytes());
    u[4..6].copy_from_slice(&u16::try_from(8 + dns.len()).unwrap().to_be_bytes());
    u.extend_from_slice(&dns);
    ipv4(ANCHOR_V4.octets(), 17, u, 6)
}

/// (protocol, source port, destination port, transport header and payload)
/// of an IPv4 packet the engine sent.
fn transport(p: &[u8]) -> Option<(u8, u16, u16, &[u8])> {
    if p.first()? >> 4 != 4 {
        return None;
    }
    let l4 = p.get(usize::from(p[0] & 15) * 4..usize::from(u16::from_be_bytes([p[2], p[3]])))?;
    Some((
        p[9],
        u16::from_be_bytes([*l4.first()?, *l4.get(1)?]),
        u16::from_be_bytes([*l4.get(2)?, *l4.get(3)?]),
        l4,
    ))
}

struct Engine {
    wire: Wire,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<io::Result<TunnelStats>>>,
    services: Arc<Hosts>,
}

impl Engine {
    /// An engine over `map`, or over the process's own map (`None`).
    fn start(map: Option<Arc<FakeIpMap>>) -> Self {
        let wire = Wire::default();
        let stop = Arc::new(AtomicBool::new(false));
        let services = Arc::new(Hosts::default());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let thread = {
            let (mut wire, stop, services) = (wire.clone(), stop.clone(), services.clone());
            thread::spawn(move || {
                let services: Arc<dyn RelayServices> = services;
                let ready = move || ready_tx.send(()).unwrap();
                let (settings, upstream) =
                    (RelaySettings::default(), "127.0.0.1:9".parse().unwrap());
                let idle = Duration::from_secs(30);
                match map {
                    Some(map) => run_ready_with_fake_ips(
                        &mut wire, settings, services, stop, 16, idle, 1280, upstream, map, ready,
                    ),
                    None => run_ready_with_services(
                        &mut wire, settings, services, stop, 16, idle, 1280, upstream, ready,
                    ),
                }
            })
        };
        ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            wire,
            stop,
            thread: Some(thread),
            services,
        }
    }

    fn send(&self, packet: Vec<u8>) {
        self.wire.to_engine.lock().unwrap().push_back(packet);
    }

    /// The next packet the engine sent that `wanted` accepts, within 3 s.
    fn next<T>(&self, wanted: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let Some(packet) = self.wire.from_engine.lock().unwrap().pop_front() else {
                thread::sleep(Duration::from_millis(1));
                continue;
            };
            if let Some(found) = wanted(&packet) {
                return Some(found);
            }
        }
        None
    }

    /// The address and TTL of the engine's answer to an A query for `name`.
    fn resolve(&self, sport: u16, id: u16, name: &str) -> (Ipv4Addr, u32) {
        self.send(a_query(sport, id, name));
        self.next(|p| {
            let (proto, from, to, udp) = transport(p)?;
            let dns = udp.get(8..)?;
            if proto != 17 || from != 53 || to != sport || dns.get(..2)? != id.to_be_bytes() {
                return None;
            }
            assert_eq!(u16::from_be_bytes([dns[6], dns[7]]), 1, "one answer");
            let rdata = dns.get(dns.len() - 4..)?;
            let ttl = dns.get(dns.len() - 10..dns.len() - 6)?;
            Some((
                Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]),
                u32::from_be_bytes([ttl[0], ttl[1], ttl[2], ttl[3]]),
            ))
        })
        .unwrap_or_else(|| panic!("no answer for {name}"))
    }

    /// The rcode and answer count of the engine's answer to an A query.
    fn answer_code(&self, sport: u16, id: u16, name: &str) -> (u8, u16) {
        self.send(a_query(sport, id, name));
        self.next(|p| {
            let (proto, from, to, udp) = transport(p)?;
            let dns = udp.get(8..)?;
            if proto != 17 || from != 53 || to != sport || dns.get(..2)? != id.to_be_bytes() {
                return None;
            }
            Some((dns[3] & 0x0f, u16::from_be_bytes([dns[6], dns[7]])))
        })
        .unwrap_or_else(|| panic!("no answer for {name}"))
    }

    /// Connect from the app's `sport` to `ip:443`, send a request and return
    /// what came back: the relayed flow's host, or how it ended.
    fn connect(&self, ip: Ipv4Addr, sport: u16) -> String {
        self.send(tcp4(ip, sport, ISN, 0, SYN, b""));
        let segment = |p: &[u8]| {
            let (proto, _, to, tcp) = transport(p)?;
            (proto == 6 && to == sport).then(|| {
                let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
                let data = usize::from(tcp[12] >> 4) * 4;
                (seq, tcp[13], tcp[data..].to_vec())
            })
        };
        let Some((seq, flags, _)) = self.next(segment) else {
            return "no answer to the SYN".into();
        };
        if flags != SYN | ACK {
            return format!("flags {flags:#x} for the SYN");
        }
        let request = tcp4(ip, sport, ISN + 1, seq.wrapping_add(1), ACK | PSH, b"hello");
        self.send(request);
        let mut answer = Vec::new();
        while let Some((_, flags, payload)) = self.next(segment) {
            answer.extend_from_slice(&payload);
            if flags & RST != 0 {
                return format!(
                    "reset after the SYN-ACK; relayed hosts {:?}",
                    self.services.hosts.lock().unwrap()
                );
            }
            if !answer.is_empty() {
                break;
            }
        }
        String::from_utf8_lossy(&answer).into_owned()
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        self.thread.take().unwrap().join().unwrap().unwrap();
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}

/// The endurance failure: a connect after the answer's 60 s TTL, while the
/// system resolver still serves that answer (up to 77 s for a 60 s answer),
/// must reach the name it was answered for, and the next answer for the
/// name must carry the same address.
#[test]
fn a_connect_after_the_answer_ttl_reaches_the_answered_name() {
    let map = Arc::new(FakeIpMap::new(FAKE_IP_POOL, FAKE_IP_RECYCLE_IDLE).unwrap());
    let engine = Engine::start(Some(map.clone()));
    let (probe, ttl) = engine.resolve(50_001, 0x1001, "endurance.example.test");
    assert_eq!(ttl, FAKE_IP_ANSWER_TTL_SECS);
    let (grace, _) = engine.resolve(50_002, 0x1002, "grace.example.test");
    // The endurance window's failing connects came 60.00 to 62.6 s after it.
    map.idle_for_test(Duration::from_secs(61));
    assert_eq!(engine.connect(probe, 41_001), "endurance.example.test");
    // The resolver's last moment for a 60 s answer: 60 + 60/4 + 2 s.
    map.idle_for_test(Duration::from_secs(16));
    assert_eq!(engine.connect(grace, 41_002), "grace.example.test");
    map.idle_for_test(Duration::from_secs(61));
    assert_eq!(
        engine.resolve(50_003, 0x1003, "grace.example.test").0,
        grace,
        "a later answer keeps the address"
    );
    assert_eq!(
        *engine.services.hosts.lock().unwrap(),
        ["endurance.example.test", "grace.example.test"]
    );
    engine.stop();
}

/// A full pool through the engine: while an open flow holds the only
/// address, long past the map's recycle idle, an answer for another name is
/// SERVFAIL with no address, and the held address still reaches its name.
#[test]
fn a_full_pool_answers_servfail_and_never_takes_an_address_a_flow_holds() {
    // One usable address (198.18.0.2) and a recycle idle the test outwaits.
    let idle = Duration::from_millis(50);
    let map = Arc::new(FakeIpMap::new("198.18.0.0/30", idle).unwrap());
    let engine = Engine::start(Some(map));
    let (ip, _) = engine.resolve(50_021, 0x3001, "held.example.test");
    // The app keeps this flow open for the rest of the test.
    assert_eq!(engine.connect(ip, 41_021), "held.example.test");
    thread::sleep(idle * 4);
    assert_eq!(
        engine.answer_code(50_022, 0x3002, "other.example.test"),
        (2, 0),
        "SERVFAIL with no answer, never the held address"
    );
    assert_eq!(engine.connect(ip, 41_022), "held.example.test");
    assert_eq!(
        *engine.services.hosts.lock().unwrap(),
        ["held.example.test", "held.example.test"]
    );
    engine.stop();
}

/// A session rebuild ends one engine run and starts the next while the
/// tunnel's DNS settings, the resolver cache and applications keep the
/// answers the first run gave. The next run must never give one of those
/// addresses to another name, and a connect to it still reaches its name.
#[test]
fn the_next_engine_run_never_gives_an_earlier_answer_to_another_name() {
    let first = Engine::start(None);
    let (ip, _) = first.resolve(50_011, 0x2001, "before-rebuild.example.test");
    first.stop();
    let second = Engine::start(None);
    let (other, _) = second.resolve(50_012, 0x2002, "after-rebuild.example.test");
    assert_ne!(
        other, ip,
        "the next run gave a cached address to another name"
    );
    assert_eq!(second.connect(ip, 41_011), "before-rebuild.example.test");
    second.stop();
}
