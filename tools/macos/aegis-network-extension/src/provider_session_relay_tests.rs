//! Armed relay services inside the composite session (B-06 S06). The test
//! relay serves aegis-server's whole secure session on every stream of every
//! connection: an ACK for each re-ACK (each on its own connection: these
//! sessions run the per-dial ACK path, which S16l falls back to; the
//! persistent ACK connection's own tests are `provider_session_link_tests`), an
//! in-process echo or DNS answer for each flow (each a stream of the
//! session's pooled flow connections, S16h). The ACK-path tests that run no
//! flow keep the first-stream-only relay.
use crate::{
    app_group::CapturedAppGroupInputs,
    bridge::{LeasedPacketBridge, PacketBridge},
    held_relay_services::{HeldRelayServices, WorkGate, RECHECK},
    provider_session::{SessionHandle, SessionPhase},
    provider_session_body::{
        spawn_armed,
        tests::{saved, store_locked},
        Trace,
    },
    test_fixture::ReadyTree,
    test_relay::{
        aaaa_query,
        pool::{PoolConfig, PooledRelay, StreamFault, StreamStep},
        AckReply, Behavior, RelayIdentity, RelayStep, TestRelay, ADMISSION_TIMEOUT, DNS_ANSWER_V6,
    },
};
use aegis_client::{
    capture_lease_gate::CaptureLeaseDeadline, packet_engine::services::RelayServices,
};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    runtime::Runtime,
};

pub(crate) type Steps = Arc<Mutex<Vec<(&'static str, Instant)>>>;
pub(crate) type ArmedHandles = (Arc<HeldRelayServices>, Arc<WorkGate>);

const MS: u64 = 1_000_000;

/// Every stream serves the whole session; only the first `acks` PolicyAcks
/// (all, for None) are answered and later ones refused.
fn serving_relay(acks: Option<usize>) -> (PooledRelay, Arc<ReadyTree>) {
    pooled_relay(|config| config.ack_limit = acks)
}

/// The multi-stream relay serving the whole session, answering every
/// PolicyAck with the tree's reply, configured further by `configure`.
fn pooled_relay(configure: impl FnOnce(&mut PoolConfig)) -> (PooledRelay, Arc<ReadyTree>) {
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let mut config = PoolConfig {
        reply: Some(AckReply::for_tree(&tree)),
        ..PoolConfig::default()
    };
    configure(&mut config);
    let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
    assert_eq!(relay.address(), tree.relay());
    (relay, tree)
}

pub(crate) fn recorder() -> (Trace, Steps) {
    let steps: Steps = Arc::default();
    let held = steps.clone();
    let trace: Trace = Arc::new(move |step| held.lock().unwrap().push((step, Instant::now())));
    (trace, steps)
}

pub(crate) fn times(steps: &Steps, wanted: &str) -> Vec<Instant> {
    steps
        .lock()
        .unwrap()
        .iter()
        .filter(|(step, _)| *step == wanted)
        .map(|(_, at)| *at)
        .collect()
}

pub(crate) fn start_armed(
    tree: &ReadyTree,
    bridge: LeasedPacketBridge,
    trace: Trace,
) -> (SessionHandle, mpsc::Receiver<SessionPhase>, ArmedHandles) {
    start_armed_within(tree, bridge, trace, Duration::from_secs(2))
}

/// `start_armed`, Ready expected within `ready`.
pub(crate) fn start_armed_within(
    tree: &ReadyTree,
    bridge: LeasedPacketBridge,
    trace: Trace,
    ready: Duration,
) -> (SessionHandle, mpsc::Receiver<SessionPhase>, ArmedHandles) {
    let claim = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    let (tx, phases) = mpsc::channel();
    let (armed_tx, armed_rx) = mpsc::channel();
    let armed_tx = Mutex::new(armed_tx);
    let session = spawn_armed(
        saved(tree),
        claim,
        move |phase| {
            let _ = tx.send(phase);
        },
        Some(trace),
        bridge,
        Arc::new(move |services, gate| {
            let _ = armed_tx.lock().unwrap().send((services, gate));
        }),
    )
    .unwrap();
    let phase = phases.recv_timeout(ready);
    assert_eq!(
        phase.ok(),
        Some(SessionPhase::Ready),
        "{:?}",
        session.refusal()
    );
    let armed = armed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    (session, phases, armed)
}

pub(crate) fn production_bridge() -> LeasedPacketBridge {
    LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default())
}

pub(crate) fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

pub(crate) async fn loopback() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let app = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (local, _) = listener.accept().await.unwrap();
    (app, local)
}

fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum = 0u32;
    for chunk in chunks {
        for pair in chunk.chunks(2) {
            let word = u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]);
            sum += u32::from(word);
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// One IPv4 or IPv6 UDP packet with valid header and UDP checksums.
pub(crate) fn udp_packet(source: SocketAddr, destination: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let mut udp = Vec::with_capacity(udp_len);
    udp.extend_from_slice(&source.port().to_be_bytes());
    udp.extend_from_slice(&destination.port().to_be_bytes());
    udp.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]);
    udp.extend_from_slice(payload);
    match (source.ip(), destination.ip()) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&[0, 17]);
            pseudo.extend_from_slice(&(udp_len as u16).to_be_bytes());
            let sum = checksum(&[&pseudo, &udp]);
            udp[6..8].copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
            let mut packet = vec![0x45, 0];
            packet.extend_from_slice(&((20 + udp_len) as u16).to_be_bytes());
            packet.extend_from_slice(&[0x12, 0x34, 0x40, 0, 64, 17, 0, 0]);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            let header = checksum(&[&packet]);
            packet[10..12].copy_from_slice(&header.to_be_bytes());
            packet.extend_from_slice(&udp);
            packet
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut pseudo = Vec::new();
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, 17]);
            let sum = checksum(&[&pseudo, &udp]);
            udp[6..8].copy_from_slice(&if sum == 0 { 0xffff } else { sum }.to_be_bytes());
            let mut packet = vec![0x60, 0, 0, 0];
            packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
            packet.extend_from_slice(&[17, 64]);
            packet.extend_from_slice(&src.octets());
            packet.extend_from_slice(&dst.octets());
            packet.extend_from_slice(&udp);
            packet
        }
        _ => panic!("mixed address families"),
    }
}

/// (source, destination, payload) of an unfragmented UDP packet.
pub(crate) fn parse_udp(packet: &[u8]) -> Option<(SocketAddr, SocketAddr, Vec<u8>)> {
    let (src, dst, udp) = match packet.first()? >> 4 {
        4 if packet.get(9) == Some(&17) => {
            let header = usize::from(packet[0] & 15) * 4;
            let src: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
            let dst: [u8; 4] = packet.get(16..20)?.try_into().ok()?;
            (
                IpAddr::from(Ipv4Addr::from(src)),
                IpAddr::from(Ipv4Addr::from(dst)),
                packet.get(header..)?,
            )
        }
        6 if packet.get(6) == Some(&17) => {
            let src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
            let dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
            (
                IpAddr::from(Ipv6Addr::from(src)),
                IpAddr::from(Ipv6Addr::from(dst)),
                packet.get(40..)?,
            )
        }
        _ => return None,
    };
    let port = |at: usize| Some(u16::from_be_bytes([*udp.get(at)?, *udp.get(at + 1)?]));
    let length = usize::from(port(4)?);
    Some((
        SocketAddr::new(src, port(0)?),
        SocketAddr::new(dst, port(2)?),
        udp.get(8..length)?.to_vec(),
    ))
}

/// Feed `packet` to the bridge as packetFlow would and wait for the reply
/// packetFlow would be handed for `from` -> `to`.
pub(crate) fn round_trip(
    bridge: &LeasedPacketBridge,
    packet: &[u8],
    from: SocketAddr,
    to: SocketAddr,
) -> Vec<u8> {
    bridge.from_os(packet).unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut delivered = None;
        bridge
            .deliver_to_os(|packet| {
                delivered = Some(packet.to_vec());
                Ok(())
            })
            .unwrap();
        if let Some((src, dst, payload)) = delivered.as_deref().and_then(parse_udp) {
            if src == from && dst == to {
                return payload;
            }
        }
        assert!(Instant::now() < deadline, "no reply from {from} to {to}");
        if delivered.is_none() {
            thread::sleep(Duration::from_millis(2));
        }
    }
}

#[test]
fn relay_udp_ipv4_and_ipv6_packets_echo_through_the_engine() {
    let (relay, tree) = serving_relay(None);
    let (trace, _steps) = recorder();
    let (mut session, phases, (_services, gate)) = start_armed(&tree, production_bridge(), trace);
    let probe = session.probe();
    let bridge = probe.bridge();
    let app4: SocketAddr = "198.19.0.10:40000".parse().unwrap();
    let echo4: SocketAddr = "192.0.2.7:7".parse().unwrap();
    let packet = udp_packet(app4, echo4, b"ipv4 over the held relay");
    assert_eq!(
        round_trip(bridge, &packet, echo4, app4),
        b"ipv4 over the held relay"
    );
    let app6: SocketAddr = "[fd00:ae61::10]:40001".parse().unwrap();
    let echo6: SocketAddr = "[2001:db8::7]:7".parse().unwrap();
    let packet = udp_packet(app6, echo6, b"ipv6 over the held relay");
    assert_eq!(
        round_trip(bridge, &packet, echo6, app6),
        b"ipv6 over the held relay"
    );
    // A non-A query to the tunnel resolver goes out as udp_once to the
    // signed upstream; the relay's answerer replies.
    let resolver: SocketAddr = "198.19.255.2:53".parse().unwrap();
    let query = aaaa_query(0x0d06, "relay.example.test");
    let answer = round_trip(bridge, &udp_packet(app4, resolver, &query), resolver, app4);
    assert!(aegis_core::dns_response::is_valid_relay_response(
        &query, &answer
    ));
    assert!(answer.ends_with(&DNS_ANSWER_V6.octets()));
    // Three UDP opens past the session's own ACK connections, each its own
    // stream.
    let opened =
        runtime().block_on(relay.wait_count(StreamStep::Opened, 3, Duration::from_secs(1)));
    assert!(opened.is_some(), "a UDP flow never opened its target");
    assert!(gate.flows() >= 2, "{} live flows", gate.flows());
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.phase(), SessionPhase::Joined);
    // Joined only after the gate drained.
    assert!(gate.is_closed());
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// One recursive A query for `name`.
fn a_query(id: u16, name: &str) -> Vec<u8> {
    let mut query = aaaa_query(id, name);
    let kind = query.len() - 3;
    query[kind] = 1;
    query
}

/// The A record of a one-answer DNS response, when it is the last record.
fn a_answer(query: &[u8], answer: &[u8]) -> Option<Ipv4Addr> {
    if answer.get(..2)? != query.get(..2)? || answer.get(6..8)? != [0, 1] {
        return None;
    }
    let ip: [u8; 4] = answer
        .get(answer.len().checked_sub(4)?..)?
        .try_into()
        .ok()?;
    Some(Ipv4Addr::from(ip))
}

const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH_ACK: u8 = 0x18;
const ACK: u8 = 0x10;

/// One IPv6 TCP segment with a valid checksum and no options.
fn tcp6_packet(
    source: SocketAddr,
    destination: SocketAddr,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let (IpAddr::V6(src), IpAddr::V6(dst)) = (source.ip(), destination.ip()) else {
        panic!("IPv6 only");
    };
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&source.port().to_be_bytes());
    tcp.extend_from_slice(&destination.port().to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&[5 << 4, flags, 0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    let sum = checksum(&[&pseudo, &tcp]);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    packet.extend_from_slice(&[6, 64]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(&tcp);
    packet
}

/// (source, destination, seq, ack, flags, payload) of an IPv6 TCP segment.
type Tcp6 = (SocketAddr, SocketAddr, u32, u32, u8, Vec<u8>);
fn parse_tcp6(packet: &[u8]) -> Option<Tcp6> {
    if packet.first()? >> 4 != 6 || *packet.get(6)? != 6 {
        return None;
    }
    let src: [u8; 16] = packet.get(8..24)?.try_into().ok()?;
    let dst: [u8; 16] = packet.get(24..40)?.try_into().ok()?;
    let tcp = packet.get(40..)?;
    let word = |at: usize| u16::from_be_bytes([tcp[at], tcp[at + 1]]);
    let long = |at: usize| u32::from_be_bytes(tcp.get(at..at + 4).unwrap().try_into().unwrap());
    let offset = usize::from(tcp.get(12)? >> 4) * 4;
    Some((
        SocketAddr::new(Ipv6Addr::from(src).into(), word(0)),
        SocketAddr::new(Ipv6Addr::from(dst).into(), word(2)),
        long(4),
        long(8),
        *tcp.get(13)?,
        tcp.get(offset..)?.to_vec(),
    ))
}

/// The next TCP segment packetFlow would be handed for `from` -> `to`.
fn next_tcp6(bridge: &LeasedPacketBridge, from: SocketAddr, to: SocketAddr) -> Tcp6 {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let mut delivered = None;
        bridge
            .deliver_to_os(|packet| {
                delivered = Some(packet.to_vec());
                Ok(())
            })
            .unwrap();
        if let Some(segment) = delivered.as_deref().and_then(parse_tcp6) {
            if segment.0 == from && segment.1 == to {
                return segment;
            }
        }
        assert!(Instant::now() < deadline, "no segment from {from} to {to}");
        if delivered.is_none() {
            thread::sleep(Duration::from_millis(2));
        }
    }
}

/// S16j-2: DNS to the IPv6 anchor through the bridge, as the kernel sends it
/// once fd00:ae61::/120 is on-link. An A question is answered locally with a
/// fake IP over UDP6 and TCP6 and opens no relay stream; an AAAA question goes
/// upstream through the relay and comes back validated.
#[test]
fn relay_dns_to_the_ipv6_anchor_is_answered_through_the_engine() {
    let (relay, tree) = serving_relay(None);
    let (trace, _steps) = recorder();
    let (mut session, phases, (_services, gate)) = start_armed(&tree, production_bridge(), trace);
    let probe = session.probe();
    let bridge = probe.bridge();
    let app6: SocketAddr = "[fd00:ae61::10]:40001".parse().unwrap();
    let anchor6: SocketAddr = "[fd00:ae61::2]:53".parse().unwrap();

    let query = a_query(0x0a06, "anchor6.example.test");
    let answer = round_trip(bridge, &udp_packet(app6, anchor6, &query), anchor6, app6);
    let fake = a_answer(&query, &answer).expect("no A answer over UDP6");
    assert_eq!(fake.octets()[..2], [198, 18], "{fake}");

    // The same name over TCP6 to the anchor: a local answer, the same fake IP.
    let client: SocketAddr = "[fd00:ae61::10]:40002".parse().unwrap();
    bridge
        .from_os(&tcp6_packet(client, anchor6, 1000, 0, SYN, &[]))
        .unwrap();
    let (_, _, server_isn, acked, flags, _) = next_tcp6(bridge, anchor6, client);
    assert_eq!((flags & 0x12, acked), (0x12, 1001), "no SYN-ACK");
    let query = a_query(0x0a07, "anchor6.example.test");
    let mut framed = (query.len() as u16).to_be_bytes().to_vec();
    framed.extend_from_slice(&query);
    let mut seq = 1001;
    bridge
        .from_os(&tcp6_packet(
            client,
            anchor6,
            seq,
            server_isn + 1,
            PSH_ACK,
            &framed,
        ))
        .unwrap();
    seq += framed.len() as u32;
    let mut received = Vec::new();
    let mut next = server_isn + 1;
    while received.len() < 2
        || received.len() < 2 + usize::from(u16::from_be_bytes([received[0], received[1]]))
    {
        let (_, _, at, _, flags, payload) = next_tcp6(bridge, anchor6, client);
        assert_eq!(flags & RST, 0, "anchor reset the TCP6 DNS flow");
        if payload.is_empty() || at != next {
            continue;
        }
        next += payload.len() as u32;
        received.extend_from_slice(&payload);
        bridge
            .from_os(&tcp6_packet(client, anchor6, seq, next, ACK, &[]))
            .unwrap();
    }
    let answer = &received[2..];
    assert_eq!(a_answer(&query, answer), Some(fake), "TCP6 A answer");
    bridge
        .from_os(&tcp6_packet(client, anchor6, seq, next, RST, &[]))
        .unwrap();
    assert_eq!(
        relay.count(StreamStep::Opened),
        0,
        "an A question opened a relay stream"
    );

    // An AAAA question to the IPv6 anchor goes upstream as udp_once.
    let query = aaaa_query(0x0a08, "anchor6.example.test");
    let answer = round_trip(bridge, &udp_packet(app6, anchor6, &query), anchor6, app6);
    assert!(aegis_core::dns_response::is_valid_relay_response(
        &query, &answer
    ));
    assert!(answer.ends_with(&DNS_ANSWER_V6.octets()));
    let opened =
        runtime().block_on(relay.wait_count(StreamStep::Opened, 1, Duration::from_secs(1)));
    assert!(
        opened.is_some(),
        "the AAAA question never reached the relay"
    );
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.phase(), SessionPhase::Joined);
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// S16j-2: packets as the read loop hands them over (`from_native`). With the
/// on-link /120 and both default routes, the kernel sends every tunnel-local
/// destination into the utun; only DNS to an anchor is served there. The
/// others are dropped before the engine and open no relay stream, while a
/// global IPv6 destination still relays. The same packet through `from_os`,
/// bypassing the filter, does reach the relay as a literal address: the
/// filter is what keeps it off.
#[test]
fn relay_native_tunnel_local_destinations_other_than_anchor_dns_never_reach_the_relay() {
    let (relay, tree) = serving_relay(None);
    let (trace, _steps) = recorder();
    let (mut session, phases, (_services, gate)) = start_armed(&tree, production_bridge(), trace);
    let probe = session.probe();
    let bridge = probe.bridge();
    let app4: SocketAddr = "198.19.0.10:40000".parse().unwrap();
    let app6: SocketAddr = "[fd00:ae61::10]:40001".parse().unwrap();
    let query = aaaa_query(0x0b06, "local.example.test");
    for (source, destination) in [
        (app6, "[fd00:ae61::3]:53"),
        (app6, "[fd00:ae61::2]:54"),
        (app6, "[fd00:ae61::ff]:7"),
        (app4, "198.19.255.3:53"),
        (app4, "198.19.255.2:54"),
    ] {
        let destination: SocketAddr = destination.parse().unwrap();
        let packet = udp_packet(source, destination, &query);
        assert!(!bridge.from_native(&packet).unwrap(), "{destination}");
    }
    let mut syn = tcp6_packet(app6, "[fd00:ae61::2]:80".parse().unwrap(), 7, 0, SYN, &[]);
    assert!(!bridge.from_native(&syn).unwrap());
    syn = tcp6_packet(app6, "[fd00:ae61::4]:53".parse().unwrap(), 7, 0, SYN, &[]);
    assert!(!bridge.from_native(&syn).unwrap());

    // A global IPv6 destination is admitted and echoes through the relay.
    let echo6: SocketAddr = "[2001:db8::7]:7".parse().unwrap();
    let packet = udp_packet(app6, echo6, b"global ipv6 still relays");
    assert!(bridge.from_native(&packet).unwrap());
    let deadline = Instant::now() + Duration::from_secs(3);
    let echoed = loop {
        let mut delivered = None;
        bridge
            .deliver_to_os(|packet| {
                delivered = Some(packet.to_vec());
                Ok(())
            })
            .unwrap();
        match delivered.as_deref().and_then(parse_udp) {
            Some((src, dst, payload)) if src == echo6 && dst == app6 => break payload,
            Some((src, ..)) => panic!("a dropped packet was answered from {src}"),
            None => {}
        }
        assert!(Instant::now() < deadline, "no echo from {echo6}");
        thread::sleep(Duration::from_millis(2));
    };
    assert_eq!(echoed, b"global ipv6 still relays");
    // Only the echo opened a stream, after a settle long enough for any
    // dropped packet to have reached the relay had it entered the engine.
    thread::sleep(Duration::from_millis(300));
    assert_eq!(
        relay.count(StreamStep::Opened),
        1,
        "a dropped packet opened a stream"
    );

    // Without the filter the engine forwards the same tunnel-local packet to
    // the relay as a literal address.
    let bypass = udp_packet(app6, "[fd00:ae61::3]:53".parse().unwrap(), &query);
    bridge.from_os(&bypass).unwrap();
    let opened =
        runtime().block_on(relay.wait_count(StreamStep::Opened, 2, Duration::from_secs(2)));
    assert!(
        opened.is_some(),
        "the unfiltered packet never reached the relay"
    );

    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.phase(), SessionPhase::Joined);
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_tcp_echo_for_6s_survives_three_reacks() {
    let (_relay, tree) = serving_relay(None);
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let lease = session.probe().bridge().refreshable_deadline();
    let first = lease.current().unwrap();
    let runtime = runtime();
    let started = Instant::now();
    let rounds = runtime.block_on(async {
        let (mut app, local) = loopback().await;
        let settings = services.signed_relay();
        let flow = {
            let services = services.clone();
            tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await })
        };
        let mut rounds = 0u32;
        while started.elapsed() < Duration::from_secs(6) {
            let sent = rounds.to_be_bytes().repeat(16);
            app.write_all(&sent).await.unwrap();
            let mut echoed = vec![0; sent.len()];
            tokio::time::timeout(Duration::from_secs(1), app.read_exact(&mut echoed))
                .await
                .expect("echo stalled")
                .unwrap();
            assert_eq!(echoed, sent);
            rounds += 1;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(gate.flows(), 1);
        app.shutdown().await.unwrap();
        let mut rest = Vec::new();
        app.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
        flow.await.unwrap().unwrap();
        rounds
    });
    let ended = Instant::now();
    assert!(rounds >= 100, "only {rounds} echo rounds");
    let during = times(&steps, "reack_renewed")
        .into_iter()
        .filter(|at| *at > started && *at < ended)
        .count();
    assert!(during >= 3, "only {during} re-ACKs during the stream");
    assert!(lease.current().unwrap() >= first + 3_000 * MS);
    assert_eq!(session.refusal(), None);
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_refused_reack_ends_the_flow_within_recheck_of_the_deadline() {
    // Only the session's first ACK is answered; every flow is still served.
    let (relay, tree) = serving_relay(Some(1));
    let (trace, steps) = recorder();
    let bridge = production_bridge();
    let clock = bridge.clone();
    let (mut session, phases, (services, gate)) = start_armed(&tree, bridge, trace);
    let deadline = clock.refreshable_deadline().current().unwrap();
    let runtime = runtime();
    let (ended_ns, last_echo_ns) = runtime.block_on(async {
        let (mut app, local) = loopback().await;
        let settings = services.signed_relay();
        let flow_clock = clock.clone();
        let flow = {
            let services = services.clone();
            tokio::spawn(async move {
                let result = services.tcp(local, &settings, "echo.test".into(), 7).await;
                (result, flow_clock.clock_ns().unwrap())
            })
        };
        let mut last_echo_ns = 0;
        let mut echoed = [0; 8];
        loop {
            if app.write_all(b"liveness").await.is_err() {
                break;
            }
            match tokio::time::timeout(Duration::from_secs(1), app.read_exact(&mut echoed)).await {
                Ok(Ok(_)) => last_echo_ns = clock.clock_ns().unwrap(),
                _ => break,
            }
            assert!(
                clock.clock_ns().unwrap() < deadline + 2_000 * MS,
                "flow outlived its lease"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let (result, ended_ns) = flow.await.unwrap();
        assert!(result.is_err());
        (ended_ns, last_echo_ns)
    });
    assert!(relay.count(StreamStep::Opened) >= 1);
    assert!(!times(&steps, "reack_failed").is_empty());
    assert!(times(&steps, "reack_renewed").is_empty());
    // The lease never moved; the flow was served up to it and ended within
    // one recheck, plus 100 ms, of it.
    assert!(
        last_echo_ns + 100 * MS >= deadline,
        "last echo {} ms before the deadline",
        deadline.saturating_sub(last_echo_ns) / MS
    );
    assert!(
        ended_ns >= deadline,
        "flow ended {} ms early",
        (deadline - ended_ns) / MS
    );
    let limit = deadline + u64::try_from(RECHECK.as_nanos()).unwrap() + 100 * MS;
    assert!(
        ended_ns <= limit,
        "flow ended {} ms after the deadline",
        (ended_ns - deadline) / MS
    );
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// S16g: right after Ready, macOS sends a burst of flows. 64 simultaneous
/// TCP flows, each establishment (S16h: each stream) paying 320 ms at the
/// relay, never put more
/// than the limiter's eleven establishments at the relay at once; the queued
/// flows all complete within their budget and the re-ACKs keep their
/// priority, so the session stays Ready throughout.
#[test]
fn relay_burst_of_64_tcp_flows_stays_under_the_cap_and_keeps_the_lease() {
    use crate::establish_limit::{ACK_RESERVE, ESTABLISH_PERMITS};
    // S16h: each establishment is a stream, and pays its 320 ms before its
    // 200, so the burst still overlaps the re-ACKs. S16h-7: 8/3 of S16g's
    // 120 ms, as flows now hold 8 permits rather than 3: the burst spans as
    // long as it did.
    let (relay, tree) = pooled_relay(|config| config.stream_setup = Duration::from_millis(320));
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let probe = session.probe();
    let limiter = services.limiter().clone();
    let settings = services.signed_relay();
    let budget = Duration::from_millis(settings.connect_timeout_ms);
    let runtime = runtime();
    let started = Instant::now();
    let results = runtime.block_on(async {
        let mut set = tokio::task::JoinSet::new();
        for tag in 0..64u8 {
            let services = services.clone();
            let settings = settings.clone();
            set.spawn(async move {
                let began = Instant::now();
                let (mut app, local) = loopback().await;
                let flow = tokio::spawn(async move {
                    services.tcp(local, &settings, "echo.test".into(), 7).await
                });
                let sent = vec![tag; 512];
                let echoed = async {
                    app.write_all(&sent).await?;
                    let mut echoed = vec![0; sent.len()];
                    app.read_exact(&mut echoed).await?;
                    app.shutdown().await?;
                    let mut rest = Vec::new();
                    app.read_to_end(&mut rest).await?;
                    anyhow::ensure!(echoed == sent && rest.is_empty(), "echo mismatch");
                    anyhow::Ok(())
                };
                let echoed = echoed.await;
                let flow = flow.await.unwrap();
                (flow.and(echoed), began.elapsed())
            });
        }
        tokio::time::timeout(Duration::from_secs(20), set.join_all())
            .await
            .expect("a queued flow hung")
    });
    let ended = Instant::now();
    // Every flow ended, each within its queue wait and establishment budget;
    // with this relay every one of them completed.
    for (result, took) in &results {
        assert!(*took < 2 * budget + Duration::from_secs(1), "{took:?}");
        assert!(result.is_ok(), "{result:?} after {took:?}");
    }
    // Never more than the cap at the relay, nor more flows than their share.
    assert!(
        relay.handshakes().high_water() <= ESTABLISH_PERMITS,
        "{} concurrent handshakes",
        relay.handshakes().high_water()
    );
    assert!(limiter.high_water() <= ESTABLISH_PERMITS);
    assert!(limiter.high_water() >= ESTABLISH_PERMITS - ACK_RESERVE);
    // The burst queued: S16j-1 serves the pool's waiters first come first
    // served, its slots exactly the flows' permits, so a flow seldom waits
    // for a permit (the limiter's `establish_queue` log, an incidental race
    // since) but the pool's queue always forms, as in S16h-7's held-services
    // burst.
    let pool_stats = services.pool().stats();
    assert!(
        pool_stats.max_waiting > ESTABLISH_PERMITS - ACK_RESERVE,
        "{pool_stats:?}"
    );
    assert_eq!(limiter.flow_timeouts(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    // The lease was renewed during the burst and never lapsed.
    let during = times(&steps, "reack_renewed")
        .into_iter()
        .filter(|at| *at > started && *at < ended)
        .count();
    assert!(
        during >= 2,
        "only {during} re-ACKs in {:?}",
        ended - started
    );
    assert!(probe.ready());
    assert_eq!(session.refusal(), None);
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// S16g: the relay answers the first ACK and then refuses every device
/// handshake with a TLS alert. The ACK path backs the session off instead of
/// redialing: after the first pre-warms only one probe dials before the
/// lease ends, and the session seals on the lease, not on a dial loop.
#[test]
fn relay_auth_refused_reack_channels_back_off_without_a_dial_loop() {
    use crate::{establish_limit::AUTH_BACKOFF, provider_session_body::PREWARM_SLOTS};
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let reply = AckReply::for_tree(&tree);
    let relay = TestRelay::spawn_each(listener, RelayIdentity::for_tree(&tree), move |index| {
        Some(if index == 0 {
            Behavior::AckThenClose {
                reply: reply.clone(),
                idle: ADMISSION_TIMEOUT,
            }
        } else {
            Behavior::AlertInner
        })
    });
    let (trace, _steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let limiter = services.limiter().clone();
    drop(services);
    let first = relay
        .wait_for(RelayStep::Alerted, Duration::from_secs(2))
        .expect("the first pre-warm was never refused");
    let deadline = Instant::now() + Duration::from_secs(6);
    while session.phase() == SessionPhase::Ready {
        assert!(Instant::now() < deadline, "the lease never ended");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    // The first ACK, the first pre-warms beside it and one probe after the
    // backoff: nothing redialed in between.
    let accepts = relay.accepts();
    assert!(
        (1 + PREWARM_SLOTS..=1 + PREWARM_SLOTS + 1).contains(&accepts),
        "{accepts} dials"
    );
    let mut alerts = vec![first];
    while let Some(at) = relay.wait_for(RelayStep::Alerted, Duration::from_millis(100)) {
        alerts.push(at);
    }
    assert_eq!(alerts.len(), accepts - 1);
    let later: Vec<_> = alerts
        .iter()
        .filter(|at| at.duration_since(first) > Duration::from_millis(500))
        .collect();
    assert!(later.len() <= 1, "{later:?}");
    for at in later {
        assert!(at.duration_since(first) >= AUTH_BACKOFF - Duration::from_millis(50));
    }
    assert_eq!(limiter.auth_failures(), u64::try_from(accepts - 1).unwrap());
    assert!(limiter.probing());
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    // The notifier saw Ready only; the seal is read from the handle.
    assert!(phases.try_recv().is_err());
}

/// S16g: the pre-warmed channels open, but the relay answers each re-ACK on
/// them with a TLS error. That is authentication class: the session backs
/// off instead of refilling and redialing, and seals on the lease.
#[test]
fn relay_tls_error_on_prewarmed_reacks_backs_off_without_redialing() {
    use crate::provider_session_body::PREWARM_SLOTS;
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let reply = AckReply::for_tree(&tree);
    let relay = TestRelay::spawn_each(listener, RelayIdentity::for_tree(&tree), move |index| {
        Some(if index == 0 {
            Behavior::AckThenClose {
                reply: reply.clone(),
                idle: ADMISSION_TIMEOUT,
            }
        } else {
            Behavior::GarbleAck
        })
    });
    let (trace, steps) = recorder();
    let (mut session, _phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let limiter = services.limiter().clone();
    drop(services);
    let deadline = Instant::now() + Duration::from_secs(6);
    while session.phase() == SessionPhase::Ready {
        assert!(Instant::now() < deadline, "the lease never ended");
        thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(session.refusal(), Some("capture_lease_expired"));
    assert!(!times(&steps, "reack_prewarm_used").is_empty());
    assert!(limiter.auth_failures() >= 1);
    // The two first pre-warms carried the request, and one refill was
    // dialed as the request took the first; nothing redialed after a failure.
    assert!(
        relay.accepts() <= 1 + PREWARM_SLOTS + 1,
        "{} dials",
        relay.accepts()
    );
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
}

/// One TCP flow through `services` to the relay's echo target; a refused
/// flow drops its local side, so the application sees the end.
pub(crate) async fn echo(
    services: Arc<HeldRelayServices>,
    settings: aegis_core::RelaySettings,
    tag: u8,
) -> anyhow::Result<()> {
    let (mut app, local) = loopback().await;
    let flow =
        tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await });
    let sent = vec![tag; 256];
    let echoed = async {
        app.write_all(&sent).await?;
        let mut echoed = vec![0; sent.len()];
        app.read_exact(&mut echoed).await?;
        anyhow::ensure!(echoed == sent, "echo mismatch");
        app.shutdown().await?;
        let mut rest = Vec::new();
        app.read_to_end(&mut rest).await?;
        anyhow::Ok(())
    };
    let echoed = echoed.await;
    flow.await??;
    echoed
}

/// Keep `outstanding` echo flows running for `span` from `started`; the
/// flows that ended, and those that completed.
fn flow_load(
    runtime: &Runtime,
    services: Arc<HeldRelayServices>,
    outstanding: usize,
    started: Instant,
    span: Duration,
) -> tokio::task::JoinHandle<(usize, usize)> {
    let settings = services.signed_relay();
    runtime.spawn(async move {
        let mut set = tokio::task::JoinSet::new();
        let (mut ended, mut completed, mut tag) = (0usize, 0usize, 0u8);
        while started.elapsed() < span {
            while set.len() < outstanding {
                set.spawn(echo(services.clone(), settings.clone(), tag));
                tag = tag.wrapping_add(1);
            }
            let left = span.saturating_sub(started.elapsed());
            if let Ok(Some(result)) = tokio::time::timeout(left, set.join_next()).await {
                ended += 1;
                completed += usize::from(matches!(result, Ok(Ok(()))));
            }
        }
        set.abort_all();
        while set.join_next().await.is_some() {}
        (ended, completed)
    })
}

/// Assert the session Ready every 20 ms until `span` after `started`; the
/// share of samples at which a flow held or waited for a permit.
fn ready_throughout(
    session: &SessionHandle,
    limiter: &crate::establish_limit::EstablishLimiter,
    started: Instant,
    span: Duration,
) -> (usize, usize) {
    let probe = session.probe();
    let (mut samples, mut establishing) = (0usize, 0usize);
    while started.elapsed() < span {
        assert_eq!(
            session.phase(),
            SessionPhase::Ready,
            "{:?} after {:?}",
            session.refusal(),
            started.elapsed()
        );
        assert!(probe.ready(), "sealed at {:?}", session.refusal());
        samples += 1;
        establishing += usize::from(limiter.flows_establishing());
        thread::sleep(Duration::from_millis(20));
    }
    (samples, establishing)
}

/// S16g against S16e's installed relay geometry: 1.45 s of setup per
/// connection, 0.85 s per PolicyAck, 2.4 s grants, about 2.15 s of lease per
/// request. Flows hold or wait for their establishment permits the whole
/// time, and the pool still keeps both pre-warm slots, so the session stays
/// Ready and renews throughout. With one slot while flows establish this
/// lease is lost within a few cycles (S16e).
#[test]
fn relay_installed_geometry_keeps_the_lease_under_continuous_flow_establishment() {
    const SETUP: Duration = Duration::from_millis(1_450);
    const REPLY: Duration = Duration::from_millis(850);
    const GRANT_MS: u64 = 2_400;
    // S16h: of each ACK connection's setup, this part is paid by every
    // stream (before its 200), so a pooled flow stream pays it too and the
    // flows keep holding or waiting for their permits.
    const STREAM: Duration = Duration::from_millis(500);
    let (relay, tree) = pooled_relay(|config| {
        config.setup = SETUP - STREAM;
        config.stream_setup = STREAM;
        config.ack_delay = REPLY;
        if let Some(reply) = config.reply.as_mut() {
            reply.effective_valid_for_ms = GRANT_MS;
        }
    });
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed_within(
        &tree,
        production_bridge(),
        trace,
        SETUP + REPLY + Duration::from_secs(3),
    );
    let limiter = services.limiter().clone();
    let runtime = runtime();
    let span = Duration::from_secs(8);
    let started = Instant::now();
    // Always more flows outstanding than flow permits.
    let load = flow_load(&runtime, services.clone(), 8, started, span);
    let (samples, establishing) = ready_throughout(&session, &limiter, started, span);
    let (ended, completed) = runtime.block_on(load).unwrap();
    assert!(
        establishing * 10 >= samples * 9,
        "flows establishing at {establishing} of {samples} samples"
    );
    assert!(completed >= 6, "{completed} of {ended} flows completed");
    let renewed = times(&steps, "reack_renewed")
        .into_iter()
        .filter(|at| *at > started)
        .count();
    assert!(renewed >= 4, "only {renewed} re-ACKs in {span:?}");
    assert_eq!(times(&steps, "reack_fresh").len(), 0);
    assert_eq!(limiter.auth_failures(), 0);
    assert_eq!(limiter.flow_refusals(), 0);
    assert!(relay.handshakes().high_water() <= crate::establish_limit::ESTABLISH_PERMITS);
    assert_eq!(session.refusal(), None);
    drop(services);
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// S16g: the relay answers every PolicyAck but ends every flow's channel
/// before its Open status (its session cap is full, which it does not count
/// as an authentication failure). Flows back off alone; the ACK path keeps
/// renewing, so the session stays Ready throughout.
#[test]
fn relay_unanswered_flow_opens_back_off_flows_alone_and_keep_the_lease() {
    let (relay, tree) = serving_relay(None);
    relay.always(Some(StreamFault::RefuseOpen));
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let limiter = services.limiter().clone();
    let runtime = runtime();
    let span = Duration::from_secs(7);
    let started = Instant::now();
    let load = flow_load(&runtime, services.clone(), 4, started, span);
    ready_throughout(&session, &limiter, started, span);
    let (ended, completed) = runtime.block_on(load).unwrap();
    assert_eq!(completed, 0);
    assert!(ended >= 4, "{ended} flows ended");
    let refusals = relay.count(StreamStep::OpenRefused);
    // A first burst, then one probe per flow backoff: never a dial loop.
    let flows = crate::establish_limit::ESTABLISH_PERMITS - crate::establish_limit::ACK_RESERVE;
    assert!(refusals >= 2, "{refusals} refused Opens");
    assert!(refusals <= flows + 5, "{refusals} refused Opens");
    // Every refusal is judged an unanswered Open, once its connection is
    // seen alive (S16h: `CONN_END_GRACE`); a flow the load cancels at its
    // end may still be within that grace.
    let judged_by = started + span - crate::flow_pool::CONN_END_GRACE - Duration::from_millis(100);
    let judgeable = relay
        .events()
        .iter()
        .filter(|event| event.step == StreamStep::OpenRefused && event.at < judged_by)
        .count();
    assert!(
        u64::try_from(judgeable).unwrap() <= limiter.flow_refusals(),
        "{judgeable} refused, {} judged",
        limiter.flow_refusals()
    );
    assert_eq!(limiter.auth_failures(), 0);
    assert!(!limiter.probing());
    let renewed = times(&steps, "reack_renewed")
        .into_iter()
        .filter(|at| *at > started)
        .count();
    assert!(renewed >= 3, "only {renewed} re-ACKs in {span:?}");
    assert_eq!(session.refusal(), None);
    drop(services);
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// S16g: after the first ACK the relay drops every connection after outer
/// TLS and before its carrier response (a restart or a path change). The
/// pre-warms' `outer_h2` failures are transport drops, not authentication
/// failures: no backoff, no probing.
#[test]
fn relay_carrier_dropped_prewarms_are_not_authentication_failures() {
    let listener = TestRelay::bind();
    let tree = Arc::new(ReadyTree::with_online_completed(
        listener.local_addr().unwrap(),
    ));
    let reply = AckReply::for_tree(&tree);
    let relay = TestRelay::spawn_each(listener, RelayIdentity::for_tree(&tree), move |index| {
        Some(if index == 0 {
            Behavior::AckThenClose {
                reply: reply.clone(),
                idle: ADMISSION_TIMEOUT,
            }
        } else {
            Behavior::DropBeforeCarrier
        })
    });
    let (trace, _steps) = recorder();
    let (mut session, _phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let limiter = services.limiter().clone();
    drop(services);
    relay
        .wait_for(RelayStep::CarrierDropped, Duration::from_secs(2))
        .expect("no pre-warm reached the relay");
    let deadline = Instant::now() + Duration::from_secs(6);
    while session.phase() == SessionPhase::Ready {
        assert!(Instant::now() < deadline, "the lease never ended");
        thread::sleep(Duration::from_millis(5));
    }
    assert!(session.refusal().is_some());
    assert_eq!(limiter.auth_failures(), 0);
    assert!(!limiter.backing_off());
    assert!(!limiter.probing());
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
}

/// S16h-6: a 90-flow burst on the pooled flow path at 170 ms RTT, with the
/// session re-ACKing throughout. The lease never lapses (Ready and armed at
/// every sample), every PolicyAck is the only stream of its own TCP
/// connection, flows never hold more than their share of permits (so the
/// ACK reserve is never taken), and the flows ride at most the pool's
/// connections.
#[test]
fn ack_path_untouched_under_pooled_burst() {
    use crate::{
        establish_limit::{ACK_RESERVE, ESTABLISH_PERMITS},
        flow_pool::POOL_CONNS,
        test_link::TestLink,
    };
    const FLOWS: u8 = 90;
    let listener = TestRelay::bind();
    let link = TestLink::spawn(listener.local_addr().unwrap());
    let tree = Arc::new(ReadyTree::with_online_completed(link.address()));
    let config = PoolConfig {
        reply: Some(AckReply::for_tree(&tree)),
        ..PoolConfig::default()
    };
    let relay = TestRelay::spawn_streams(listener, RelayIdentity::for_tree(&tree), config);
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) =
        start_armed_within(&tree, production_bridge(), trace, Duration::from_secs(6));
    let limiter = services.limiter().clone();
    let settings = services.signed_relay();
    let runtime = runtime();
    let span = Duration::from_secs(8);
    let started = Instant::now();
    let burst = {
        let services = services.clone();
        runtime.spawn(async move {
            let mut set = tokio::task::JoinSet::new();
            for tag in 0..FLOWS {
                set.spawn(echo(services.clone(), settings.clone(), tag));
            }
            let mut completed = 0usize;
            while let Some(result) = set.join_next().await {
                completed += usize::from(matches!(result, Ok(Ok(()))));
            }
            completed
        })
    };
    let probe = session.probe();
    let mut max_flow_permits = 0;
    while started.elapsed() < span {
        assert_eq!(
            session.phase(),
            SessionPhase::Ready,
            "{:?} after {:?}",
            session.refusal(),
            started.elapsed()
        );
        assert!(probe.ready(), "sealed at {:?}", session.refusal());
        max_flow_permits = max_flow_permits.max(limiter.active().1);
        thread::sleep(Duration::from_millis(10));
    }
    let completed = runtime.block_on(burst).unwrap();
    // No lease gap: re-ACKs renewed the lease throughout the burst.
    let renewed = times(&steps, "reack_renewed")
        .into_iter()
        .filter(|at| *at > started)
        .count();
    assert!(renewed >= 3, "only {renewed} re-ACKs in {span:?}");
    assert_eq!(session.refusal(), None);
    // Flows never took the ACK reserve.
    assert!(max_flow_permits <= ESTABLISH_PERMITS - ACK_RESERVE);
    assert!(limiter.high_water() <= ESTABLISH_PERMITS);
    assert_eq!(limiter.auth_failures(), 0);
    assert!(completed > 0, "no flow completed");
    // Every ACK establishment on its own TCP connection, its only stream;
    // every flow a stream of at most the pool's connections.
    let events = relay.events();
    let streams_of = |conn: usize| {
        events
            .iter()
            .filter(|event| event.conn == conn && event.step == StreamStep::Accepted)
            .count()
    };
    let mut ack_conns = Vec::new();
    for event in events
        .iter()
        .filter(|event| event.step == StreamStep::Acked)
    {
        assert_eq!(streams_of(event.conn), 1, "ACK conn {}", event.conn);
        ack_conns.push(event.conn);
    }
    // The first ACK and every renewal.
    assert!(ack_conns.len() > renewed);
    let flow_conns: std::collections::BTreeSet<usize> = events
        .iter()
        .filter(|event| event.step == StreamStep::Opened)
        .map(|event| event.conn)
        .collect();
    assert!(flow_conns.iter().all(|conn| !ack_conns.contains(conn)));
    // At most the pool's connections at once. Over the burst a connection
    // may drain (a stream that waited past idle reuse for one of the 16
    // flow permits is given back) and another be dialed in its place.
    let stats = services.pool().stats();
    assert!(stats.max_conns <= POOL_CONNS, "{stats:?} {flow_conns:?}");
    assert!(
        stats.max_establishing <= crate::flow_pool::H_CONN,
        "{stats:?}"
    );
    assert_eq!(relay.strikes(), 0);
    drop(services);
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_first_flow_after_running_rides_the_session_predial() {
    // S16i-1: a Ready session dials nothing for flows until its epoch is
    // Running; then it pre-dials pooled connections (S16j-1: two at once),
    // and the first flow takes one, opening no TCP connection of its own.
    let (relay, tree) = serving_relay(None);
    let (trace, _steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let limiter = services.limiter().clone();
    let pool = services.pool().clone();
    // S16m: the session's verified PolicyAck proved the pool at Ready.
    assert!(pool.proven(), "the session's ACK left the pool unproven");
    thread::sleep(Duration::from_millis(200));
    assert_eq!(pool.stats().dials, 0);
    assert!(pool.views().is_empty());
    limiter.mark_epoch_running();
    let deadline = Instant::now() + Duration::from_secs(2);
    while pool.views().len() < crate::flow_pool::PREWARM_CONNS {
        assert!(Instant::now() < deadline, "no pre-dials after Running");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(pool.stats().prewarms, 2);
    // The pre-dial holds no live flow and no permit once ready.
    assert_eq!(limiter.live(), 0);
    assert_eq!(limiter.active().1, 0);
    let runtime = runtime();
    let echoed = runtime.block_on(echo(services.clone(), services.signed_relay(), 7));
    assert!(echoed.is_ok(), "{echoed:?}");
    let stats = pool.stats();
    assert_eq!((stats.dials, stats.prewarms), (2, 2), "{stats:?}");
    // The flow's stream rode a connection that carried no ACK.
    let events = relay.events();
    let opened: Vec<usize> = events
        .iter()
        .filter(|event| event.step == StreamStep::Opened)
        .map(|event| event.conn)
        .collect();
    assert_eq!(opened.len(), 1, "{events:?}");
    assert!(!events
        .iter()
        .any(|event| event.conn == opened[0] && event.step == StreamStep::Acked));
    let lines = limiter.flow_log_lines();
    assert!(
        lines.contains(&"pool_prewarm dialed".to_owned()),
        "{lines:?}"
    );
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("flow_open ok ms:")),
        "{lines:?}"
    );
    // One round of pre-dials per session, however long it runs.
    thread::sleep(Duration::from_millis(1_500));
    assert_eq!(pool.stats().prewarms, 2);
    assert_eq!(session.refusal(), None);
    drop((services, pool));
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

/// One TCP echo flow kept open after its first echo until its session ends
/// it; `up` hears once the echo came back.
async fn held_echo(
    services: Arc<HeldRelayServices>,
    settings: aegis_core::RelaySettings,
    tag: u8,
    up: tokio::sync::mpsc::UnboundedSender<()>,
) -> anyhow::Result<()> {
    let (mut app, local) = loopback().await;
    let flow =
        tokio::spawn(async move { services.tcp(local, &settings, "echo.test".into(), 7).await });
    let sent = vec![tag; 256];
    app.write_all(&sent).await?;
    let mut echoed = vec![0; sent.len()];
    app.read_exact(&mut echoed).await?;
    anyhow::ensure!(echoed == sent, "echo mismatch");
    let _ = up.send(());
    // Held until the session's stop ends the flow.
    let mut rest = Vec::new();
    let _ = app.read_to_end(&mut rest).await;
    let _ = flow.await;
    Ok(())
}

/// A Running session's pre-dials, joined into its pool: their connection ids.
fn predialed(services: &HeldRelayServices) -> std::collections::BTreeSet<u64> {
    let pool = services.pool();
    services.limiter().mark_epoch_running();
    let deadline = Instant::now() + Duration::from_secs(2);
    while pool.views().len() < crate::flow_pool::PREWARM_CONNS {
        assert!(Instant::now() < deadline, "no pre-dials after Running");
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(pool.stats().prewarms, crate::flow_pool::PREWARM_CONNS);
    pool.views().iter().map(|view| view.id).collect()
}

/// Open `count` held echo flows on `runtime` and wait until every one has
/// echoed; their tasks.
fn hold_flows(
    runtime: &Runtime,
    services: &Arc<HeldRelayServices>,
    count: usize,
) -> Vec<tokio::task::JoinHandle<anyhow::Result<()>>> {
    let (up, mut ups) = tokio::sync::mpsc::unbounded_channel();
    let settings = services.signed_relay();
    let flows: Vec<_> = (0..count)
        .map(|tag| {
            runtime.spawn(held_echo(
                services.clone(),
                settings.clone(),
                u8::try_from(tag % 256).unwrap(),
                up.clone(),
            ))
        })
        .collect();
    runtime.block_on(async {
        for _ in 0..count {
            tokio::time::timeout(Duration::from_secs(10), ups.recv())
                .await
                .expect("flows never all echoed")
                .unwrap();
        }
    });
    flows
}

/// Seal and join `session`: whether it joined, and how long that took.
fn timed_stop(session: &mut SessionHandle) -> (bool, Duration) {
    let stopping = Instant::now();
    let joined = session.try_join(Duration::from_secs(2));
    (joined, stopping.elapsed())
}

#[test]
fn relay_stop_joins_with_a_live_predialed_connection() {
    // S16j-3, the v21 stop's exit 70: a pre-dial runs on the session's
    // current-thread runtime, so the driver of the connection it dialed does
    // too. Flows riding that connection keep it pooled until the stop, whose
    // relay drain must then drive that runtime to drop the aborted driver.
    let (relay, tree) = serving_relay(None);
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let pool = services.pool().clone();
    let predialed = predialed(&services);
    let runtime = runtime();
    let flows = hold_flows(&runtime, &services, 8);
    // Live flows ride a pre-dialed connection.
    assert!(
        pool.views()
            .iter()
            .any(|view| predialed.contains(&view.id) && view.streams > 0),
        "{:?} {predialed:?}",
        pool.views()
    );
    // Past the pre-dials' unused-close wait: only the driver is left.
    thread::sleep(crate::flow_pool::IDLE_REUSE + Duration::from_millis(300));
    assert!(pool.views().iter().any(|view| predialed.contains(&view.id)));
    assert_eq!(session.refusal(), None);
    drop(services);
    let (joined, took) = timed_stop(&mut session);
    assert!(joined, "not joined after {took:?}");
    assert!(took < Duration::from_millis(500), "{took:?}");
    assert!(gate.drained());
    assert!(times(&steps, "relay_drain_pending").is_empty());
    assert!(!store_locked(&tree.identity_dir()));
    for flow in flows {
        runtime.block_on(flow).unwrap().unwrap();
    }
    assert_eq!(relay.strikes(), 0);
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_stop_during_predial_close_unused_window_joins() {
    // S16j-3: with no flow at all, a stop while the pre-dial tasks still
    // wait out their unused-close rule on the session runtime.
    let (relay, tree) = serving_relay(None);
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let pool = services.pool().clone();
    let predialed = predialed(&services);
    thread::sleep(Duration::from_millis(300));
    // Both still pooled, unused, and their pre-dial tasks still waiting.
    assert_eq!(
        pool.views()
            .iter()
            .map(|view| view.id)
            .collect::<std::collections::BTreeSet<_>>(),
        predialed
    );
    assert!(gate.tasks_left() >= crate::flow_pool::PREWARM_CONNS);
    drop((services, pool));
    let (joined, took) = timed_stop(&mut session);
    assert!(joined, "not joined after {took:?}");
    assert!(took < Duration::from_millis(500), "{took:?}");
    assert!(gate.drained());
    assert!(times(&steps, "relay_drain_pending").is_empty());
    assert!(!store_locked(&tree.identity_dir()));
    assert_eq!(relay.strikes(), 0);
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_stop_drains_many_pooled_flows_across_both_runtimes_in_time() {
    // S16j-3 at scale: the pre-dialed connections' drivers on the session
    // runtime, further pooled connections dialed by flows on another one,
    // and flows up to most of the test tree's live cap on all of them. The
    // whole stop, seal to Joined, stays far inside the provider's budget,
    // and every gate permit returns.
    const FLOWS: usize = 48;
    let (relay, tree) = serving_relay(None);
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let pool = services.pool().clone();
    assert!(FLOWS < services.limiter().live_cap());
    let predialed = predialed(&services);
    let runtime = runtime();
    let flows = hold_flows(&runtime, &services, FLOWS);
    assert_eq!(gate.flows(), FLOWS);
    let views = pool.views();
    assert_eq!(
        views.iter().map(|view| view.streams).sum::<usize>(),
        FLOWS,
        "{views:?}"
    );
    assert!(
        views
            .iter()
            .any(|view| predialed.contains(&view.id) && view.streams > 0),
        "{views:?} {predialed:?}"
    );
    assert!(
        views.iter().any(|view| !predialed.contains(&view.id)),
        "{views:?} {predialed:?}"
    );
    assert_eq!(session.refusal(), None);
    drop(services);
    let (joined, took) = timed_stop(&mut session);
    assert!(joined, "not joined after {took:?}");
    assert!(took < Duration::from_millis(500), "{took:?}");
    assert!(gate.drained());
    assert_eq!(gate.flows(), 0);
    assert!(times(&steps, "relay_drain_pending").is_empty());
    assert!(!store_locked(&tree.identity_dir()));
    for flow in flows {
        runtime.block_on(flow).unwrap().unwrap();
    }
    assert_eq!(relay.strikes(), 0);
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_stop_holds_the_store_while_a_flow_holds_its_permit() {
    // S16j-3: the bounded first drain attempt only reports a stuck gate,
    // once (`relay_drain_pending`); the Store is released only after it
    // drained, however many attempts that takes.
    let (_relay, tree) = serving_relay(None);
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let permit = gate.admit().unwrap();
    drop(services);
    let stopping = Instant::now();
    // Past the first attempt and through a second full one.
    assert!(!session.try_join(Duration::from_secs(2)));
    assert!(!session.try_join(Duration::from_millis(800)));
    assert!(store_locked(&tree.identity_dir()));
    assert!(times(&steps, "relay_join").is_empty());
    let pending = times(&steps, "relay_drain_pending");
    assert_eq!(pending.len(), 1);
    let after = pending[0].duration_since(stopping);
    assert!(
        after >= crate::provider_session_body::RELAY_DRAIN_FIRST
            && after < crate::provider_session_body::RELAY_DRAIN_FIRST + Duration::from_millis(400),
        "{after:?}"
    );
    drop(permit);
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert_eq!(times(&steps, "relay_drain_pending").len(), 1);
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_stop_drain_starts_no_reack_or_ack_prewarm() {
    // S16j-3: the relay drain drives the session runtime, so the monitor is
    // polled while a flow holds its permit. A forced re-ACK falling due then
    // starts no PolicyAck and frees no pre-warm slot to redial.
    use crate::provider_session_body::REACK_SPACING;
    let (_relay, tree) = serving_relay(None);
    let (trace, steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let probe = session.probe();
    let permit = gate.admit().unwrap();
    drop(services);
    // A renewal on the 3 s test ACKs: the next attempt is about 750 ms after
    // it began and nothing is in flight.
    let deadline = Instant::now() + Duration::from_secs(5);
    let began = loop {
        let attempts = times(&steps, "reack_attempt");
        let renewed = times(&steps, "reack_renewed");
        if let (Some(&began), Some(&done)) = (attempts.last(), renewed.last()) {
            if done >= began {
                break began;
            }
        }
        assert!(Instant::now() < deadline, "no renewal");
        thread::sleep(Duration::from_millis(1));
    };
    // A forced request is due from here on, the next lease attempt later.
    let due = began + REACK_SPACING + Duration::from_millis(30);
    thread::sleep(due.saturating_duration_since(Instant::now()));
    session.seal("provider_stop");
    let deadline = Instant::now() + Duration::from_secs(1);
    let stopped = loop {
        if let Some(&at) = times(&steps, "bridge_stop").first() {
            break at;
        }
        assert!(Instant::now() < deadline, "no bridge_stop");
        thread::sleep(Duration::from_millis(1));
    };
    // Only the drain polls the monitor now.
    probe.request_reack();
    thread::sleep(crate::provider_session_body::RELAY_DRAIN_FIRST + Duration::from_millis(200));
    assert_eq!(times(&steps, "relay_drain_pending").len(), 1);
    assert!(times(&steps, "relay_join").is_empty());
    drop(permit);
    assert!(session.try_join(Duration::from_secs(2)));
    assert_eq!(session.refusal(), Some("provider_stop"));
    for step in ["reack_attempt", "reack_forced", "reack_prewarm_start"] {
        let late: Vec<_> = times(&steps, step)
            .into_iter()
            .filter(|at| *at > stopped)
            .collect();
        assert!(late.is_empty(), "{step} after bridge_stop: {late:?}");
    }
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}

#[test]
fn relay_session_binds_its_live_cap_to_the_signed_max_flows() {
    // S16i-2: the limiter is built before the packet config is verified;
    // by the time the session is armed its live cap is the signed bundle's
    // `max_flows` (the test tree signs 64), under the relay's bound.
    use crate::establish_limit::{live_cap, LIVE_FLOWS};
    let (_relay, tree) = serving_relay(None);
    let (trace, _steps) = recorder();
    let (mut session, phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let limiter = services.limiter().clone();
    assert_eq!(limiter.live_cap(), live_cap(64));
    assert_eq!(limiter.live_cap(), 64);
    assert!(limiter.live_cap() < LIVE_FLOWS);
    let echoed = runtime().block_on(echo(services.clone(), services.signed_relay(), 7));
    assert!(echoed.is_ok(), "{echoed:?}");
    assert_eq!(session.refusal(), None);
    drop((services, limiter));
    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
    assert!(phases.try_recv().is_err());
}
