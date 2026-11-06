//! B-06 S20c: a post-connect flow burst through the real shared engine.
//!
//! Installed v24 (r13, r15) lost the tail of both bursts in about 1.7 s
//! with no flow refusal of the session logged for them: the shared engine
//! keeps four listening sockets per destination port between two polls, and
//! answered every further SYN of the same poll with a RST. The device now
//! hands the engine at most `SYNS_PER_PORT_PER_POLL` SYNs of one port per
//! batch; these tests drive raw IPv4 segments through `PacketEngineOwner`
//! to relay services that answer after a 170 ms round trip.
use super::*;
use crate::bridge::PacketBridge;
use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
use std::collections::HashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RTT: Duration = Duration::from_millis(170);
const SRC: [u8; 4] = [198, 19, 255, 1];
const DST: [u8; 4] = [203, 0, 113, 7];
const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

fn admitted_bridge() -> LeasedPacketBridge {
    let deadline = CaptureLeaseDeadline::default();
    deadline.replace(Some(u64::MAX)).unwrap();
    LeasedPacketBridge::new(PacketBridge::default(), deadline)
}

fn checksum(parts: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for part in parts {
        for pair in part.chunks(2) {
            let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One IPv4 TCP segment from the app (`SRC:sport`) to `DST:dport`.
fn tcp4(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let tcp_len = 20 + payload.len();
    let total = 20 + tcp_len;
    let mut p = vec![0u8; total];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    p[6] = 0x40;
    p[8] = 64;
    p[9] = 6;
    p[12..16].copy_from_slice(&SRC);
    p[16..20].copy_from_slice(&DST);
    let ip = checksum(&[&p[..20]]);
    p[10..12].copy_from_slice(&ip.to_be_bytes());
    let t = 20;
    p[t..t + 2].copy_from_slice(&sport.to_be_bytes());
    p[t + 2..t + 4].copy_from_slice(&dport.to_be_bytes());
    p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
    p[t + 8..t + 12].copy_from_slice(&ack.to_be_bytes());
    p[t + 12] = 0x50;
    p[t + 13] = flags;
    p[t + 14..t + 16].copy_from_slice(&0xffffu16.to_be_bytes());
    p[t + 20..].copy_from_slice(payload);
    let pseudo = [&SRC[..], &DST[..], &[0, 6], &(tcp_len as u16).to_be_bytes()].concat();
    let sum = checksum(&[&pseudo, &p[t..]]);
    p[t + 16..t + 18].copy_from_slice(&sum.to_be_bytes());
    p
}

/// One IPv6 TCP segment with no extension header.
fn tcp6(dport: u16, flags: u8) -> Vec<u8> {
    let mut p = vec![0u8; 60];
    p[0] = 0x60;
    p[4..6].copy_from_slice(&20u16.to_be_bytes());
    p[6] = 6;
    p[7] = 64;
    p[40..42].copy_from_slice(&40_000u16.to_be_bytes());
    p[42..44].copy_from_slice(&dport.to_be_bytes());
    p[52] = 0x50;
    p[53] = flags;
    p
}

/// A segment the engine sent to the app: (app port, seq, ack, flags, payload).
fn parse(p: &[u8]) -> Option<(u16, u32, u32, u8, Vec<u8>)> {
    if p.first()? >> 4 != 4 || *p.get(9)? != 6 {
        return None;
    }
    let t = usize::from(p[0] & 15) * 4;
    let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
    let data = usize::from(p.get(t + 12)? >> 4) * 4;
    let word = |at: usize| u32::from_be_bytes([p[at], p[at + 1], p[at + 2], p[at + 3]]);
    Some((
        u16::from_be_bytes([p[t + 2], p[t + 3]]),
        word(t + 4),
        word(t + 8),
        p[t + 13],
        p.get(t + data..total)?.to_vec(),
    ))
}

/// Relay services whose every TCP flow answers one round trip late, then
/// echoes; each flow's call is counted.
#[derive(Default)]
struct SlowEcho {
    calls: AtomicUsize,
}
impl EventSink for SlowEcho {
    fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
}
impl RelayServices for SlowEcho {
    fn tcp<'a>(
        &'a self,
        mut local: TcpStream,
        _: &'a RelaySettings,
        _: String,
        _: u16,
    ) -> RelayWork<'a, ()> {
        self.calls.fetch_add(1, Ordering::AcqRel);
        Box::pin(async move {
            tokio::time::sleep(RTT).await;
            let mut buf = [0u8; 256];
            loop {
                let n = local.read(&mut buf).await?;
                if n == 0 {
                    return Ok(());
                }
                local.write_all(&buf[..n]).await?;
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

#[derive(Debug, Default)]
struct BurstResult {
    echoed: usize,
    reset: usize,
    relayed: usize,
    first_echo: Option<Duration>,
    /// Packets the bridge input refused (a full queue ends the session).
    refused: usize,
    sealed: bool,
}

/// How the app completes each answered SYN.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Reply {
    /// One ACK|PSH segment carrying its request.
    Combined,
    /// S16o, as the macOS client does: the handshake's pure ACK, then a
    /// separate request segment.
    Split,
}

/// `flows` SYNs to one destination port, all queued at once right after the
/// engine is constructed; each answered SYN is completed with one request
/// whose echo must come back through the relay services.
fn burst(flows: u16) -> BurstResult {
    burst_with(flows, Reply::Combined)
}

fn burst_with(flows: u16, reply: Reply) -> BurstResult {
    let bridge = admitted_bridge();
    let services = Arc::new(SlowEcho::default());
    let mut owner = PacketEngineOwner::spawn(
        bridge.clone(),
        PacketEngineConfig {
            relay: RelaySettings::default(),
            max_flows: 256,
            idle: Duration::from_secs(30),
            mtu: 1280,
            dns_upstream: "127.0.0.1:9".parse().unwrap(),
        },
        services.clone(),
    )
    .unwrap();
    owner
        .wait_engine_constructed(Duration::from_secs(2))
        .unwrap();
    owner.ready_under_lease().unwrap();
    const ISN: u32 = 1_000;
    let mut answered: HashMap<u16, bool> = HashMap::new();
    let mut result = BurstResult::default();
    let start = Instant::now();
    for i in 0..flows {
        bridge
            .from_os(&tcp4(40_000 + i, 80, ISN, 0, SYN, b""))
            .unwrap();
    }
    let deadline = start + Duration::from_secs(5);
    while Instant::now() < deadline && result.echoed + result.reset < usize::from(flows) {
        let Some(packet) = bridge.to_os().unwrap() else {
            thread::sleep(Duration::from_millis(1));
            continue;
        };
        let Some((port, seq, _ack, flags, payload)) = parse(&packet) else {
            continue;
        };
        if flags & RST != 0 {
            result.reset += 1;
            answered.insert(port, true);
        } else if flags & (SYN | ACK) == SYN | ACK && !answered.contains_key(&port) {
            answered.insert(port, false);
            let ack = seq.wrapping_add(1);
            let segments = match reply {
                Reply::Combined => vec![tcp4(port, 80, ISN + 1, ack, ACK | PSH, b"ping")],
                Reply::Split => vec![
                    tcp4(port, 80, ISN + 1, ack, ACK, b""),
                    tcp4(port, 80, ISN + 1, ack, ACK | PSH, b"ping"),
                ],
            };
            for segment in segments {
                match bridge.from_os(&segment) {
                    Ok(()) => {}
                    Err(error) => {
                        assert_eq!(error.kind(), io::ErrorKind::WouldBlock, "{error}");
                        result.refused += 1;
                    }
                }
            }
        } else if payload == b"ping" && answered.get(&port) == Some(&false) {
            answered.insert(port, true);
            result.echoed += 1;
            result.first_echo.get_or_insert(start.elapsed());
        }
    }
    result.relayed = services.calls.load(Ordering::Acquire);
    result.sealed = bridge.is_sealed();
    owner.stop_handle().stop();
    let _ = owner.try_join(Duration::from_secs(2));
    assert!(owner.owned_children_joined());
    result
}

#[test]
fn post_connect_burst_of_24_reaches_the_relay_with_no_reset() {
    let result = burst(24);
    assert_eq!(result.reset, 0, "{result:?}");
    assert_eq!(result.echoed, 24, "{result:?}");
    assert_eq!(result.relayed, 24, "{result:?}");
    assert!(result.first_echo.is_some_and(|at| at >= RTT), "{result:?}");
}

#[test]
fn post_connect_burst_of_90_reaches_the_relay_with_no_reset() {
    let result = burst(90);
    assert_eq!(result.reset, 0, "{result:?}");
    assert_eq!(result.echoed, 90, "{result:?}");
    assert_eq!(result.relayed, 90, "{result:?}");
    assert!(result.first_echo.is_some_and(|at| at >= RTT), "{result:?}");
}

/// S16o: the macOS client answers each SYN-ACK with a pure ACK and then its
/// request, both queued behind the SYNs still held back. Pacing the SYNs
/// must not slow the bridge input's drain: ending the engine's batch at the
/// first held SYN took about four SYNs per poll while each admitted one
/// queued two more frames, so 90 SYNs at once overflowed the 128-frame input
/// queue (`WouldBlock`, which seals the session: `packet_io_failed`).
#[test]
fn split_replies_to_a_burst_of_90_never_overflow_the_bridge_input() {
    let result = burst_with(90, Reply::Split);
    assert_eq!(result.refused, 0, "{result:?}");
    assert!(!result.sealed, "{result:?}");
    assert_eq!(result.reset, 0, "{result:?}");
    assert_eq!(result.echoed, 90, "{result:?}");
    assert_eq!(result.relayed, 90, "{result:?}");
}

/// `split_replies_to_a_burst_of_90_never_overflow_the_bridge_input` with
/// 120 SYNs at once, near the input queue's 128 frames.
#[test]
fn split_replies_to_a_burst_of_120_never_overflow_the_bridge_input() {
    let result = burst_with(120, Reply::Split);
    assert_eq!(result.refused, 0, "{result:?}");
    assert!(!result.sealed, "{result:?}");
    assert_eq!(result.reset, 0, "{result:?}");
    assert_eq!(result.echoed, 120, "{result:?}");
}

fn device() -> (LeasedPacketBridge, NePacketDevice) {
    let bridge = admitted_bridge();
    let device = NePacketDevice::new(bridge.clone(), Arc::new(AtomicBool::new(false)));
    (bridge, device)
}

#[test]
fn syn_port_reads_only_connection_opening_tcp() {
    assert_eq!(tcp_syn_port(&tcp4(1, 80, 0, 0, SYN, b"")), Some(80));
    assert_eq!(tcp_syn_port(&tcp6(443, SYN)), Some(443));
    assert_eq!(tcp_syn_port(&tcp4(1, 80, 0, 0, SYN | ACK, b"")), None);
    assert_eq!(tcp_syn_port(&tcp4(1, 80, 0, 0, SYN | RST, b"")), None);
    assert_eq!(tcp_syn_port(&tcp4(1, 80, 0, 0, ACK, b"")), None);
    assert_eq!(tcp_syn_port(&tcp6(443, ACK)), None);
    // A UDP datagram whose payload carries SYN-like bytes at the offset.
    let mut udp = tcp4(1, 80, 0, 0, SYN, b"");
    udp[9] = 17;
    assert_eq!(tcp_syn_port(&udp), None);
    // A later IPv4 fragment: its payload holds no TCP header.
    let mut fragment = tcp4(1, 80, 0, 0, SYN, b"");
    fragment[6] = 0x00;
    fragment[7] = 0x02;
    assert_eq!(tcp_syn_port(&fragment), None);
    // An IPv6 packet with an extension header first.
    let mut extended = tcp6(443, SYN);
    extended[6] = 0;
    assert_eq!(tcp_syn_port(&extended), None);
    // An IPv4 header length below 20 bytes, whose bytes from 16 on would
    // read as a SYN.
    let mut short = tcp4(1, 80, 0, 0x5002_0000, SYN, b"");
    short[0] = 0x44;
    assert_eq!(tcp_syn_port(&short), None);
    assert_eq!(tcp_syn_port(&[0x45, 0, 0]), None);
    assert_eq!(tcp_syn_port(&[]), None);
}

#[test]
fn device_holds_the_fifth_syn_of_a_port_for_the_next_batch_in_order() {
    let (bridge, mut device) = device();
    let syn = |port: u16, sport: u16| tcp4(sport, port, 0, 0, SYN, b"");
    let sent = [
        syn(80, 1),
        syn(80, 2),
        syn(80, 3),
        syn(80, 4),
        tcp4(5, 80, 0, 0, SYN | ACK, b""),
        tcp4(6, 80, 0, 0, ACK, b""),
        syn(443, 7),
        syn(80, 8),
        tcp4(9, 80, 0, 0, ACK, b""),
        syn(80, 10),
        syn(443, 11),
    ];
    for packet in &sent {
        bridge.from_os(packet).unwrap();
    }
    // S16o: the fifth and sixth SYNs to port 80 are held; every packet
    // behind them joins this batch, which only the empty read ends.
    for index in [0, 1, 2, 3, 4, 5, 6, 8, 10] {
        assert_eq!(device.receive().unwrap().as_ref(), Some(&sent[index]));
    }
    assert_eq!(device.receive().unwrap(), None);
    // The next batch starts with the held SYNs, in order.
    for index in [7, 9] {
        assert_eq!(device.receive().unwrap().as_ref(), Some(&sent[index]));
    }
    assert_eq!(device.receive().unwrap(), None);
}

/// S16o: a batch releases at most `SYNS_PER_PORT_PER_POLL` held SYNs per
/// port, oldest first, and a held SYN of another port is not held up by
/// them; the held SYNs a device keeps are bounded (`MAX_HELD_SYNS`), the
/// rest dropped for the app to retransmit.
#[test]
fn held_syns_are_released_per_port_per_batch_and_bounded() {
    let (bridge, mut device) = device();
    // Twelve SYNs to port 80, then one to 443: the first four of port 80 and
    // the one to 443 join the first batch.
    let mut sent: Vec<Vec<u8>> = (1..=12)
        .map(|sport| tcp4(sport, 80, 0, 0, SYN, b""))
        .collect();
    sent.push(tcp4(13, 443, 0, 0, SYN, b""));
    for packet in &sent {
        bridge.from_os(packet).unwrap();
    }
    for index in [0, 1, 2, 3, 12] {
        assert_eq!(device.receive().unwrap().as_ref(), Some(&sent[index]));
    }
    assert_eq!(device.receive().unwrap(), None);
    for batch in [4..8, 8..12] {
        for index in batch {
            assert_eq!(device.receive().unwrap().as_ref(), Some(&sent[index]));
        }
        assert_eq!(device.receive().unwrap(), None);
    }
    // Past `MAX_HELD_SYNS` held SYNs, a SYN is dropped. The bridge holds
    // 128 frames, so they are queued in parts.
    let total = MAX_HELD_SYNS + 4 + 10;
    let mut read = 0;
    for part in (0..total).collect::<Vec<_>>().chunks(100) {
        for sport in part {
            let sport = u16::try_from(1000 + sport).unwrap();
            bridge.from_os(&tcp4(sport, 80, 0, 0, SYN, b"")).unwrap();
        }
        while device.receive().unwrap().is_some() {
            read += 1;
        }
        // One batch per part, which its empty read ends: four SYNs.
    }
    assert!(read <= total, "{read}");
    assert_eq!(device.pace.held.len(), MAX_HELD_SYNS);
    let dropped = device.pace.dropped;
    assert_eq!(read + MAX_HELD_SYNS + dropped, total);
    assert!(dropped > 0);
}

#[test]
fn an_empty_read_ends_the_batch() {
    let (bridge, mut device) = device();
    for sport in 1..=4 {
        bridge.from_os(&tcp4(sport, 80, 0, 0, SYN, b"")).unwrap();
        assert!(device.receive().unwrap().is_some());
    }
    assert_eq!(device.receive().unwrap(), None);
    let fifth = tcp4(5, 80, 0, 0, SYN, b"");
    bridge.from_os(&fifth).unwrap();
    assert_eq!(device.receive().unwrap(), Some(fifth));
}

#[test]
fn the_engine_batch_bound_ends_the_batch() {
    let (bridge, mut device) = device();
    let ack = tcp4(9, 80, 0, 0, ACK, b"");
    // Four SYNs to port 80, then ACKs up to `ENGINE_BATCH` reads, queued in
    // parts (the bridge holds 128) and never read empty.
    let mut queued: Vec<Vec<u8>> = (1..=4)
        .map(|sport| tcp4(sport, 80, 0, 0, SYN, b""))
        .collect();
    queued.extend(std::iter::repeat_n(ack.clone(), ENGINE_BATCH - 4));
    for part in queued.chunks(100) {
        for packet in part {
            bridge.from_os(packet).unwrap();
        }
        for packet in part {
            assert_eq!(device.receive().unwrap().as_ref(), Some(packet));
        }
    }
    // The engine polls after `ENGINE_BATCH` reads: a fifth SYN to the same
    // port joins its next batch at once.
    let fifth = tcp4(5, 80, 0, 0, SYN, b"");
    bridge.from_os(&fifth).unwrap();
    assert_eq!(device.receive().unwrap(), Some(fifth));
}

#[test]
fn a_held_syn_is_dropped_with_a_stopped_device() {
    let bridge = admitted_bridge();
    let stop = Arc::new(AtomicBool::new(false));
    let mut device = NePacketDevice::new(bridge.clone(), stop.clone());
    for sport in 1..=5 {
        bridge.from_os(&tcp4(sport, 80, 0, 0, SYN, b"")).unwrap();
    }
    for _ in 0..4 {
        assert!(device.receive().unwrap().is_some());
    }
    assert_eq!(device.receive().unwrap(), None);
    stop.store(true, Ordering::Release);
    assert!(device.receive().is_err());
}

// S16o: the flows a lost session's engine answered, reset by the next one.

/// Relay services whose every TCP flow waits for a relay stream that never
/// comes, as r13's tcp_echo_v4 did while the pool ramped.
struct NeverRelayed;
impl EventSink for NeverRelayed {
    fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
}
impl RelayServices for NeverRelayed {
    fn tcp<'a>(
        &'a self,
        local: TcpStream,
        _: &'a RelaySettings,
        _: String,
        _: u16,
    ) -> RelayWork<'a, ()> {
        Box::pin(async move {
            let _held = local;
            std::future::pending().await
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

fn engine_on(bridge: &LeasedPacketBridge, ledger: &flows::FlowLedger) -> PacketEngineOwner {
    let mut owner = PacketEngineOwner::spawn_on_ledger(
        bridge.clone(),
        PacketEngineConfig {
            relay: RelaySettings::default(),
            max_flows: 16,
            idle: Duration::from_secs(30),
            mtu: 1280,
            dns_upstream: "127.0.0.1:9".parse().unwrap(),
        },
        Arc::new(NeverRelayed),
        ledger.clone(),
    )
    .unwrap();
    owner
        .wait_engine_constructed(Duration::from_secs(2))
        .unwrap();
    owner
}

/// The next segment the engine sent to app port `port` matching `wanted`.
fn next_to(
    bridge: &LeasedPacketBridge,
    port: u16,
    wanted: impl Fn(u32, u32, u8, &[u8]) -> bool,
) -> (u32, u32, u8) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        let Some(packet) = bridge.to_os().unwrap() else {
            thread::sleep(Duration::from_millis(1));
            continue;
        };
        if let Some((to, seq, ack, flags, payload)) = parse(&packet) {
            if to == port && wanted(seq, ack, flags, &payload) {
                return (seq, ack, flags);
            }
        }
    }
    panic!("nothing to port {port}");
}

/// IPv4 header and TCP checksums of `packet` both verify.
fn checksums_verify(packet: &[u8]) -> bool {
    let header = usize::from(packet[0] & 15) * 4;
    let tcp = &packet[header..];
    let length = u16::try_from(tcp.len()).unwrap().to_be_bytes();
    let pseudo = [&packet[12..20], &[0, 6], &length[..]].concat();
    checksum(&[&packet[..header]]) == 0 && checksum(&[&pseudo, tcp]) == 0
}

/// S16o: r13's cold first echo. The engine acknowledged a flow's request
/// while the flow waited for a relay stream, then its session was lost (the
/// lease lapsed and sealed its bridge), so the app had nothing to
/// retransmit and hung for its whole timeout. Now the epoch's next engine
/// resets every flow the lost one answered and never closed, at the
/// sequence number the app expects next, and no other.
#[test]
fn a_lost_engines_answered_flows_are_reset_by_the_next_session() {
    const ISN: u32 = 7_000;
    let ledger = flows::FlowLedger::default();
    let lost = admitted_bridge();
    let mut owner = engine_on(&lost, &ledger);
    let mut answered = HashMap::new();
    for port in [40_001, 40_002, 40_003] {
        lost.from_os(&tcp4(port, 80, ISN, 0, SYN, b"")).unwrap();
        let (seq, _, _) = next_to(&lost, port, |_, _, flags, _| flags == SYN | ACK);
        answered.insert(port, seq.wrapping_add(1));
        lost.from_os(&tcp4(port, 80, ISN + 1, seq.wrapping_add(1), ACK, b""))
            .unwrap();
    }
    // 40001's request is acknowledged and never answered.
    lost.from_os(&tcp4(
        40_001,
        80,
        ISN + 1,
        answered[&40_001],
        ACK | PSH,
        b"ping",
    ))
    .unwrap();
    next_to(&lost, 40_001, |_, ack, flags, _| {
        flags & ACK != 0 && ack == ISN + 5
    });
    // 40003 is reset by the app: closed, so never reset again.
    lost.from_os(&tcp4(40_003, 80, ISN + 1, answered[&40_003], RST, b""))
        .unwrap();
    thread::sleep(Duration::from_millis(50));
    // The lease lapsed: the bridge is sealed and the engine ends.
    lost.stop();
    let _ = owner.try_join(Duration::from_secs(2));
    assert!(owner.owned_children_joined());
    assert_eq!(ledger.pending(), 2);
    assert_eq!(ledger.resets(), 0);

    let rebuilt = admitted_bridge();
    let mut next = engine_on(&rebuilt, &ledger);
    let mut resets = HashMap::new();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && resets.len() < 2 {
        let Some(packet) = rebuilt.to_os().unwrap() else {
            thread::sleep(Duration::from_millis(1));
            continue;
        };
        assert!(checksums_verify(&packet));
        assert_eq!(&packet[12..16], &DST);
        assert_eq!(&packet[16..20], &SRC);
        let (port, seq, ack, flags, payload) = parse(&packet).unwrap();
        assert_eq!(flags, RST | ACK);
        assert!(payload.is_empty());
        assert_eq!(u16::from_be_bytes([packet[20], packet[21]]), 80);
        resets.insert(port, (seq, ack));
    }
    assert_eq!(
        resets,
        HashMap::from([
            (40_001, (answered[&40_001], ISN + 5)),
            (40_002, (answered[&40_002], ISN + 1)),
        ])
    );
    thread::sleep(Duration::from_millis(50));
    assert_eq!(rebuilt.to_os().unwrap(), None, "a third reset");
    assert_eq!(ledger.resets(), 2);
    assert_eq!(ledger.pending(), 0);
    assert!(!rebuilt.is_sealed());
    next.stop_handle().stop();
    let _ = next.try_join(Duration::from_secs(2));
    assert!(next.owned_children_joined());
}

fn v4(last: u8) -> std::net::IpAddr {
    std::net::IpAddr::from([198, 19, 255, last])
}

fn seg(from_app: bool, port: u16, seq: u32, ack: u32, flags: u8, payload: u32) -> flows::Segment {
    let (app, remote) = (v4(1), std::net::IpAddr::from(DST));
    let (src, dst, sport, dport) = if from_app {
        (app, remote, port, 443)
    } else {
        (remote, app, 443, port)
    };
    flows::Segment {
        src,
        dst,
        sport,
        dport,
        seq,
        ack,
        flags,
        payload,
    }
}

/// `flows` handed to a fresh ledger: each orphan's (app port, seq, ack).
fn orphans_of(mut tracked: flows::Flows) -> Vec<(u16, u32, u32)> {
    let ledger = flows::FlowLedger::default();
    ledger.orphan(&mut tracked);
    let mut orphans: Vec<(u16, u32, u32)> = ledger
        .take(usize::MAX, |_| false)
        .iter()
        .map(|orphan| {
            let reset = orphan.reset().unwrap();
            let (port, seq, ack, flags, _) = parse(&reset).unwrap();
            assert_eq!(flags, RST | ACK);
            assert!(checksums_verify(&reset));
            (port, seq, ack)
        })
        .collect();
    orphans.sort_unstable();
    orphans
}

/// S16o: a flow's sequence numbers follow both directions (SYN and FIN
/// count, a retransmission never moves them back); a RST either way or a
/// FIN both ways ends it; a SYN the engine never answered is no orphan.
#[test]
fn tracked_flows_follow_sequence_numbers_and_end_on_reset_or_both_fins() {
    let mut tracked = flows::Flows::default();
    // 1: SYN 100, SYN-ACK 5000, ten bytes up, twenty down, an old
    // retransmission of each.
    tracked.app_sent(&seg(true, 1, 100, 0, SYN, 0));
    tracked.engine_sent(&seg(false, 1, 5_000, 101, SYN | ACK, 0));
    tracked.app_sent(&seg(true, 1, 101, 5_001, ACK | PSH, 10));
    tracked.engine_sent(&seg(false, 1, 5_001, 111, ACK | PSH, 20));
    tracked.app_sent(&seg(true, 1, 101, 5_001, ACK | PSH, 5));
    tracked.engine_sent(&seg(false, 1, 5_001, 111, ACK, 10));
    // 2: the engine's RST ends it. 3: the app's RST. 4: FIN both ways.
    // 5: never answered. 6: the app's FIN alone (half closed).
    for port in 2..=6 {
        tracked.app_sent(&seg(true, port, 10, 0, SYN, 0));
    }
    for port in [2, 3, 4, 6] {
        tracked.engine_sent(&seg(false, port, 900, 11, SYN | ACK, 0));
    }
    tracked.engine_sent(&seg(false, 2, 901, 11, RST | ACK, 0));
    tracked.app_sent(&seg(true, 3, 11, 901, RST, 0));
    tracked.app_sent(&seg(true, 4, 11, 901, FIN | ACK, 0));
    tracked.engine_sent(&seg(false, 4, 901, 12, FIN | ACK, 0));
    tracked.app_sent(&seg(true, 6, 11, 901, FIN | ACK, 0));
    // A segment of a flow never opened here is not tracked.
    tracked.engine_sent(&seg(false, 7, 1, 1, ACK, 3));
    assert_eq!(tracked.len(), 3);
    // Sequence wrap: a SYN at u32::MAX.
    tracked.app_sent(&seg(true, 8, u32::MAX, 0, SYN, 0));
    tracked.engine_sent(&seg(false, 8, u32::MAX - 1, 0, SYN | ACK, 4));
    tracked.app_sent(&seg(true, 8, 0, 4, ACK, 2));
    assert_eq!(
        orphans_of(tracked),
        [(1, 5_021, 111), (6, 901, 12), (8, 3, 2)]
    );
}

#[test]
fn an_ipv6_orphan_reset_is_a_valid_segment_to_the_app() {
    let app: std::net::IpAddr = "fd00::1".parse().unwrap();
    let remote: std::net::IpAddr = "2001:db8::7".parse().unwrap();
    let mut tracked = flows::Flows::default();
    let segment = |(src, sport), (dst, dport), seq, ack, flags| flows::Segment {
        src,
        dst,
        sport,
        dport,
        seq,
        ack,
        flags,
        payload: 0,
    };
    tracked.app_sent(&segment((app, 50_000), (remote, 443), 1, 0, SYN));
    tracked.engine_sent(&segment((remote, 443), (app, 50_000), 77, 2, SYN | ACK));
    let ledger = flows::FlowLedger::default();
    ledger.orphan(&mut tracked);
    let reset = ledger.take(8, |_| false)[0].reset().unwrap();
    let parsed = flows::segment(&reset).unwrap();
    assert_eq!(
        parsed,
        segment((remote, 443), (app, 50_000), 78, 2, RST | ACK)
    );
    let pseudo = [&reset[8..40], &[0, 0, 0, 20, 0, 0, 0, 6][..]].concat();
    assert_eq!(checksum(&[&pseudo, &reset[40..]]), 0);
    assert!(crate::bridge::validate_packet(&reset).is_ok());
}

/// Flows `1..=n` (app ports) answered, handed to `ledger` as orphans.
fn orphan_into(ledger: &flows::FlowLedger, n: u16) {
    let mut tracked = flows::Flows::default();
    for port in 1..=n {
        tracked.app_sent(&seg(true, port, 10, 0, SYN, 0));
        tracked.engine_sent(&seg(false, port, 900, 11, SYN | ACK, 0));
    }
    ledger.orphan(&mut tracked);
}

/// S16o: a device resets at most `RESETS_PER_BATCH` orphans per batch, and
/// none while its output holds `RESET_OUTPUT_ROOM` frames (the room the
/// app's other output keeps), going on once it was written.
#[test]
fn orphan_resets_are_paced_per_batch_and_by_output_room() {
    let bridge = admitted_bridge();
    let ledger = flows::FlowLedger::default();
    orphan_into(&ledger, 40);
    let mut device = NePacketDevice::on_ledger(
        bridge.clone(),
        Arc::new(AtomicBool::new(false)),
        ledger.clone(),
    );
    for batch in 1..=4 {
        assert_eq!(device.receive().unwrap(), None);
        assert_eq!(bridge.output_len(), batch * flows::RESETS_PER_BATCH);
    }
    assert_eq!(bridge.output_len(), flows::RESET_OUTPUT_ROOM);
    assert_eq!(device.receive().unwrap(), None);
    assert_eq!(bridge.output_len(), flows::RESET_OUTPUT_ROOM);
    assert_eq!(ledger.pending(), 8);
    while bridge.to_os().unwrap().is_some() {}
    assert_eq!(device.receive().unwrap(), None);
    assert_eq!(bridge.output_len(), 8);
    assert_eq!(ledger.pending(), 0);
    assert_eq!(ledger.resets(), 40);
    assert!(!bridge.is_sealed());
}

/// v26 audit merge: a reset that meets a full output queue is dropped and
/// counted like any engine packet; it neither seals the bridge nor fails
/// the device. A sealed bridge still fails.
#[test]
fn an_orphan_reset_on_a_full_output_is_dropped_and_counted_never_sealing() {
    let bridge = admitted_bridge();
    let ledger = flows::FlowLedger::default();
    orphan_into(&ledger, 3);
    let orphans = ledger.take(flows::RESETS_PER_BATCH, |_| false);
    assert_eq!(orphans.len(), 3);
    let filler = tcp4(9, 443, 10, 0, ACK, b"");
    for _ in 0..crate::bridge::MAX_PACKETS {
        bridge.engine_send(&filler).unwrap();
    }
    assert_eq!(send_resets(&bridge, &orphans).unwrap(), 0);
    assert_eq!(bridge.dropped_outbound(), 3);
    assert!(!bridge.is_sealed());
    // A drained slot takes the next reset.
    assert_eq!(bridge.to_os().unwrap(), Some(filler));
    assert_eq!(send_resets(&bridge, &orphans[..1]).unwrap(), 1);
    assert_eq!(bridge.dropped_outbound(), 3);
    assert!(!bridge.is_sealed());
    bridge.stop();
    assert!(send_resets(&bridge, &orphans[..1]).is_err());
}

/// S16o: an orphan whose connection the next engine already serves (the
/// app reached it on the same ports) is dropped, not reset.
#[test]
fn an_orphan_the_next_engine_serves_is_not_reset() {
    let bridge = admitted_bridge();
    let ledger = flows::FlowLedger::default();
    let mut device = NePacketDevice::on_ledger(
        bridge.clone(),
        Arc::new(AtomicBool::new(false)),
        ledger.clone(),
    );
    // App port 1 to the same remote end opens on this engine, then the
    // lost engine's flows of app ports 1 and 2 reach the ledger.
    bridge.from_os(&tcp4(1, 443, 10, 0, SYN, b"")).unwrap();
    assert!(device.receive().unwrap().is_some());
    assert_eq!(device.receive().unwrap(), None);
    orphan_into(&ledger, 2);
    // The next batch resets port 2 alone.
    assert_eq!(device.receive().unwrap(), None);
    let mut ports = Vec::new();
    while let Some(reset) = bridge.to_os().unwrap() {
        ports.push(parse(&reset).unwrap().0);
    }
    assert_eq!(ports, [2]);
    assert_eq!(ledger.resets(), 1);
}

/// v25 merge: the S16o resets a device writes back to the app go out on the
/// tunnel interface, which the S20b leak guard allows while it is armed for
/// the epoch; the same bytes on a physical interface are not relay traffic
/// and drop, so the guard really is armed here.
#[test]
fn orphan_resets_to_the_app_pass_the_armed_leak_guard_on_the_tunnel() {
    use crate::leak_guard::{filter_packet, Counters, Gate, Peer, Verdict};
    let ledger = flows::FlowLedger::default();
    orphan_into(&ledger, 3);
    let mut resets: Vec<Vec<u8>> = ledger
        .take(usize::MAX, |_| false)
        .iter()
        .map(|orphan| orphan.reset().unwrap())
        .collect();
    let app: std::net::IpAddr = "fd00::1".parse().unwrap();
    let remote: std::net::IpAddr = "2001:db8::7".parse().unwrap();
    let mut tracked = flows::Flows::default();
    let segment = |(src, sport), (dst, dport), seq, ack, flags| flows::Segment {
        src,
        dst,
        sport,
        dport,
        seq,
        ack,
        flags,
        payload: 0,
    };
    tracked.app_sent(&segment((app, 50_000), (remote, 443), 1, 0, SYN));
    tracked.engine_sent(&segment((remote, 443), (app, 50_000), 77, 2, SYN | ACK));
    let ledger6 = flows::FlowLedger::default();
    ledger6.orphan(&mut tracked);
    resets.push(ledger6.take(8, |_| false)[0].reset().unwrap());
    assert_eq!(resets.len(), 4);

    let gate = Gate::new();
    let relay = Peer {
        ip: std::net::IpAddr::from([192, 0, 2, 10]),
        port: 443,
    };
    let _token = gate.arm(Some(relay), false);
    let counters = Counters::new();
    for reset in &resets {
        assert_eq!(flows::segment(reset).unwrap().flags, RST | ACK);
        for direction in [0, 1, 2] {
            for name in ["utun0", "utun4"] {
                assert_eq!(
                    filter_packet(&gate, &counters, Some(name.as_bytes()), direction, reset),
                    Verdict::Allow,
                    "{name} {direction}"
                );
            }
            assert_eq!(
                filter_packet(&gate, &counters, Some(b"en0"), direction, reset),
                Verdict::Drop,
                "en0 {direction}"
            );
        }
    }
}

/// S20g: only the engine's first SYN-ACK of a flow the device saw open is
/// an answered open: not a retransmitted SYN-ACK, data, a RST, a SYN-ACK
/// before which the engine sent something else, or one of a flow never
/// opened here or already reset.
#[test]
fn only_the_engines_first_syn_ack_of_a_tracked_flow_is_an_answered_open() {
    let mut tracked = flows::Flows::default();
    tracked.app_sent(&seg(true, 1, 100, 0, SYN, 0));
    assert!(!tracked.engine_sent(&seg(false, 1, 5_000, 101, ACK, 0)));
    assert!(tracked.engine_sent(&seg(false, 1, 5_000, 101, SYN | ACK, 0)));
    assert!(!tracked.engine_sent(&seg(false, 1, 5_000, 101, SYN | ACK, 0)));
    assert!(!tracked.engine_sent(&seg(false, 1, 5_001, 101, ACK | PSH, 10)));
    assert!(!tracked.engine_sent(&seg(false, 2, 900, 11, SYN | ACK, 0)));
    tracked.app_sent(&seg(true, 3, 10, 0, SYN, 0));
    assert!(!tracked.engine_sent(&seg(false, 3, 900, 11, RST | ACK, 0)));
    assert!(!tracked.engine_sent(&seg(false, 3, 900, 11, SYN | ACK, 0)));
    // A new SYN of the same connection after its reset opens it again.
    tracked.app_sent(&seg(true, 3, 50, 0, SYN, 0));
    assert!(tracked.engine_sent(&seg(false, 3, 700, 51, SYN | ACK, 0)));
}

#[test]
fn engine_flow_open_port_classes() {
    use flows::PortClass;
    for (port, class) in [
        (9, PortClass::Discard),
        (53, PortClass::Dns),
        (80, PortClass::Web),
        (443, PortClass::Web),
        (8080, PortClass::Web),
        (0, PortClass::Low),
        (7, PortClass::Low),
        (10, PortClass::Low),
        (1023, PortClass::Low),
        (1024, PortClass::High),
        (8443, PortClass::High),
        (u16::MAX, PortClass::High),
    ] {
        assert_eq!(PortClass::of(port), class, "port {port}");
    }
    let codes: Vec<&str> = PortClass::ALL.iter().map(|c| c.code()).collect();
    assert_eq!(
        codes,
        [
            "class:discard",
            "class:dns",
            "class:web",
            "class:low",
            "class:high"
        ]
    );
}

/// (class, n, wall) of each `engine_flow_open` line.
fn open_lines(log: &flows::OpenLog) -> Vec<(String, u64, f64)> {
    log.lines()
        .iter()
        .map(|line| {
            let fields: Vec<&str> = line.split(' ').collect();
            assert_eq!(fields.len(), 4, "{line}");
            assert_eq!(fields[0], "engine_flow_open");
            #[cfg(all(target_os = "macos", feature = "apple"))]
            assert!(
                crate::apple::stable_fields(fields[0], &fields[1..]),
                "{line}"
            );
            let wall = fields[3].strip_prefix("wall:").unwrap();
            let (secs, micros) = wall.split_once('.').unwrap();
            assert!(
                secs.bytes().all(|b| b.is_ascii_digit()) && micros.len() == 6,
                "{line}"
            );
            (
                fields[1].strip_prefix("class:").unwrap().to_string(),
                fields[2].strip_prefix("n:").unwrap().parse().unwrap(),
                wall.parse().unwrap(),
            )
        })
        .collect()
}

/// S20g: every `discard` open is logged (up to `DISCARD_LINES`), each with
/// the class's count so far and the wall time; another class at most once
/// per `OPEN_CLASS_LOG_EVERY`, its next line counting the flows held back.
#[test]
fn engine_flow_opens_log_every_discard_open_and_other_classes_once_a_second() {
    let mut log = flows::OpenLog::default();
    let before = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let t0 = Instant::now();
    for _ in 0..3 {
        log.answered(9, t0);
    }
    log.answered(443, t0);
    log.answered(80, t0 + Duration::from_millis(500));
    log.answered(8080, t0 + Duration::from_millis(999));
    log.answered(443, t0 + flows::OPEN_CLASS_LOG_EVERY);
    log.answered(53, t0);
    log.answered(22, t0);
    log.answered(40_000, t0);
    log.answered(40_001, t0);
    let after = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    let lines = open_lines(&log);
    let got: Vec<(&str, u64)> = lines.iter().map(|(c, n, _)| (c.as_str(), *n)).collect();
    assert_eq!(
        got,
        [
            ("discard", 1),
            ("discard", 2),
            ("discard", 3),
            ("web", 1),
            ("web", 4),
            ("dns", 1),
            ("low", 1),
            ("high", 1),
        ]
    );
    for (_, _, wall) in &lines {
        assert!(*wall >= before - 0.001 && *wall <= after + 0.001, "{wall}");
    }
    // The discard lines stop at DISCARD_LINES; the count goes on.
    let mut log = flows::OpenLog::default();
    for _ in 0..flows::DISCARD_LINES + 5 {
        log.answered(9, t0);
    }
    let lines = open_lines(&log);
    assert_eq!(lines.len() as u64, flows::DISCARD_LINES);
    assert_eq!(lines.last().unwrap().1, flows::DISCARD_LINES);
}

/// One IPv4 TCP segment from `DST:sport` to the app at `SRC:dport`.
fn tcp4_to_app(sport: u16, dport: u16, seq: u32, ack: u32, flags: u8) -> Vec<u8> {
    let mut p = tcp4(sport, dport, seq, ack, flags, b"");
    p[12..16].copy_from_slice(&DST);
    p[16..20].copy_from_slice(&SRC);
    p
}

/// S20g: the device logs the engine's answer to an app's SYN to port 9 as
/// one `discard` open; the SYN alone, the SYN-ACK's retransmission and a
/// RST towards another app's SYN log nothing.
#[test]
fn the_device_logs_the_engines_answer_to_a_discard_syn_once() {
    let (bridge, mut device) = device();
    let syn = tcp4(47_100, 9, 1_000, 0, SYN, b"");
    let other = tcp4(47_101, 9, 2_000, 0, SYN, b"");
    for packet in [&syn, &other] {
        bridge.from_os(packet).unwrap();
        assert_eq!(device.receive().unwrap().as_ref(), Some(packet));
    }
    assert!(device.opens.lines().is_empty());
    let synack = tcp4_to_app(9, 47_100, 7_000, 1_001, SYN | ACK);
    device.send(&synack).unwrap();
    device.send(&synack).unwrap();
    device
        .send(&tcp4_to_app(9, 47_101, 0, 2_001, RST | ACK))
        .unwrap();
    let lines = open_lines(&device.opens);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!((lines[0].0.as_str(), lines[0].1), ("discard", 1));
}

/// Relay services that record each TCP flow's host and answer every read
/// with that host.
#[derive(Default)]
struct RecordingHosts {
    hosts: std::sync::Mutex<Vec<String>>,
}
impl EventSink for RecordingHosts {
    fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
}
impl RelayServices for RecordingHosts {
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
                let n = local.read(&mut buf).await?;
                if n == 0 {
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

/// `tcp4` from the app's `sport` to `dst:443`.
fn tcp4_443(dst: [u8; 4], sport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut p = tcp4(sport, 443, seq, ack, flags, payload);
    p[16..20].copy_from_slice(&dst);
    p[10..12].copy_from_slice(&[0, 0]);
    let ip = checksum(&[&p[..20]]);
    p[10..12].copy_from_slice(&ip.to_be_bytes());
    let tcp_len = u16::try_from(p.len() - 20).unwrap();
    p[36..38].copy_from_slice(&[0, 0]);
    let pseudo = [&SRC[..], &dst[..], &[0, 6], &tcp_len.to_be_bytes()].concat();
    let sum = checksum(&[&pseudo, &p[20..]]);
    p[36..38].copy_from_slice(&sum.to_be_bytes());
    p
}

/// rc=35 (v35/v36 load windows): an app that gave up its connect before
/// the engine's SYN-ACK arrived (a happy-eyeballs loser closed in SYN_SENT)
/// has its kernel answer the SYN-ACK with a RST. smoltcp returns a socket
/// that takes a RST in SYN-RECEIVED to LISTEN with its tuple cleared, while
/// the engine still held it as the abandoned flow, bridged to that flow's
/// relay work. The next SYN to the same port, for any destination, must
/// reach a relay flow of its own, never the abandoned flow's channel.
///
/// `gap` separates the RST from the next SYN: with a gap the engine sees
/// the socket back in LISTEN; back to back (normally one engine batch) the
/// socket has already taken the next SYN when the engine next looks at it.
fn next_syn_after_a_reset_syn_received(gap: Option<Duration>) {
    const ISN: u32 = 1_000;
    const ABANDONED: [u8; 4] = [203, 0, 113, 7];
    const NEXT: [u8; 4] = [203, 0, 113, 8];
    let bridge = admitted_bridge();
    let services = Arc::new(RecordingHosts::default());
    let mut owner = PacketEngineOwner::spawn(
        bridge.clone(),
        PacketEngineConfig {
            relay: RelaySettings::default(),
            max_flows: 16,
            idle: Duration::from_secs(30),
            mtu: 1280,
            dns_upstream: "127.0.0.1:9".parse().unwrap(),
        },
        services.clone(),
    )
    .unwrap();
    owner
        .wait_engine_constructed(Duration::from_secs(2))
        .unwrap();
    owner.ready_under_lease().unwrap();
    // The abandoned connect: its SYN is answered, and the app's kernel,
    // which no longer has the socket, resets the SYN-ACK (RFC 9293: at its
    // ACK number, no ACK flag).
    bridge
        .from_os(&tcp4_443(ABANDONED, 41_000, ISN, 0, SYN, b""))
        .unwrap();
    let (_, ack, _) = next_to(&bridge, 41_000, |_, _, flags, _| flags == SYN | ACK);
    assert_eq!(ack, ISN + 1);
    bridge
        .from_os(&tcp4_443(ABANDONED, 41_000, ISN + 1, 0, RST, b""))
        .unwrap();
    if let Some(gap) = gap {
        thread::sleep(gap);
    }
    // Another app's connection to another destination on the same port.
    bridge
        .from_os(&tcp4_443(NEXT, 41_001, ISN, 0, SYN, b""))
        .unwrap();
    let (seq, _, _) = next_to(&bridge, 41_001, |_, _, flags, _| flags == SYN | ACK);
    bridge
        .from_os(&tcp4_443(
            NEXT,
            41_001,
            ISN + 1,
            seq.wrapping_add(1),
            ACK | PSH,
            b"hello",
        ))
        .unwrap();
    let mut answer = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline && answer.len() < 11 {
        let Some(packet) = bridge.to_os().unwrap() else {
            thread::sleep(Duration::from_millis(1));
            continue;
        };
        if let Some((41_001, _, _, _, payload)) = parse(&packet) {
            answer.extend_from_slice(&payload);
        }
    }
    let hosts = services.hosts.lock().unwrap().clone();
    owner.stop_handle().stop();
    let _ = owner.try_join(Duration::from_secs(2));
    assert_eq!(
        String::from_utf8_lossy(&answer),
        "203.0.113.8",
        "the next connection's bytes went to relay flows {hosts:?}"
    );
    assert_eq!(hosts, ["203.0.113.7", "203.0.113.8"]);
}

#[test]
fn rst_in_syn_received_never_splices_the_next_syn_into_the_old_flow() {
    next_syn_after_a_reset_syn_received(Some(Duration::from_millis(100)));
}

#[test]
fn rst_and_the_next_syn_back_to_back_never_splice_into_the_old_flow() {
    next_syn_after_a_reset_syn_received(None);
}
