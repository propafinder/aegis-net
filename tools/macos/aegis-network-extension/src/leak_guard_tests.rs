//! S20b verdict rules over synthetic frames. No packet is sent or captured.
use super::*;
use std::sync::Arc;

const LOCAL: [u8; 4] = [192, 168, 1, 50];
const GATEWAY: [u8; 4] = [192, 168, 1, 1];
const PEER: [u8; 4] = [198, 51, 100, 9];
const RELAY: [u8; 4] = [203, 0, 113, 10];
const RELAY_PORT: u16 = 443;
const AUTHORITY_PORT: u16 = 9445;

fn local6() -> Ipv6Addr {
    "2001:db8:1:2::50".parse().unwrap()
}
fn peer6() -> Ipv6Addr {
    "2001:db8:ffff::9".parse().unwrap()
}
fn relay6() -> Ipv6Addr {
    "2001:db8:443::10".parse().unwrap()
}
fn link_local() -> Ipv6Addr {
    "fe80::1c".parse().unwrap()
}
fn gateway6() -> Ipv6Addr {
    "fe80::1".parse().unwrap()
}

fn peer(ip: IpAddr, port: u16) -> Peer {
    Peer { ip, port }
}
fn relay4() -> Peer {
    peer(IpAddr::V4(Ipv4Addr::from(RELAY)), RELAY_PORT)
}
fn authority4() -> Peer {
    peer(IpAddr::V4(Ipv4Addr::from(RELAY)), AUTHORITY_PORT)
}

// v31 (S23b): the gate arms the relay alone. Updated from S20b, whose
// helper also took the enrollment authority's endpoint.
fn guarding(relay: Option<Peer>, udp_relay: bool) -> Snapshot {
    Snapshot {
        mode: Mode::Guarding,
        token: 7,
        relays: PeerSet::one(relay),
        udp_relay,
        udp_media: PeerSet::EMPTY,
    }
}
/// The production shape: the relay on its IPv4 host, whose enrollment
/// authority (`authority4`, the same host) v31 no longer arms.
fn armed() -> Snapshot {
    guarding(Some(relay4()), false)
}
fn armed6() -> Snapshot {
    guarding(Some(peer(IpAddr::V6(relay6()), RELAY_PORT)), false)
}

fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02];
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
fn vlan(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![
        0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02, 0x81, 0x00, 0x00, 0x07,
    ];
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}
fn v4_full(src: [u8; 4], dst: [u8; 4], proto: u8, ttl: u8, fragment: u16, l4: &[u8]) -> Vec<u8> {
    let total = (20 + l4.len()) as u16;
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0x12, 0x34]);
    packet.extend_from_slice(&fragment.to_be_bytes());
    packet.extend_from_slice(&[ttl, proto, 0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(l4);
    packet
}
fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, l4: &[u8]) -> Vec<u8> {
    v4_full(src, dst, proto, 64, 0x4000, l4)
}
fn v6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop: u8, rest: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&(rest.len() as u16).to_be_bytes());
    packet.extend_from_slice(&[next, hop]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(rest);
    packet
}
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;
const RST: u8 = 0x04;
const FIN_ACK: u8 = 0x11;
fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::new();
    segment.extend_from_slice(&sport.to_be_bytes());
    segment.extend_from_slice(&dport.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    segment.extend_from_slice(payload);
    segment
}
fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut datagram = Vec::new();
    datagram.extend_from_slice(&sport.to_be_bytes());
    datagram.extend_from_slice(&dport.to_be_bytes());
    datagram.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    datagram
}
fn icmp(kind: u8, code: u8, rest: &[u8]) -> Vec<u8> {
    let mut message = vec![kind, code, 0, 0, 0, 0, 0, 0];
    message.extend_from_slice(rest);
    message
}
/// A hop-by-hop, routing or destination options header of `units` + 1
/// eight-octet units.
fn ext(next: u8, units: u8) -> Vec<u8> {
    let mut header = vec![next, units];
    header.resize((usize::from(units) + 1) * 8, 0);
    header
}
fn frag6(next: u8, offset_units: u16, more: bool) -> Vec<u8> {
    let field = (offset_units << 3) | u16::from(more);
    let mut header = vec![next, 0];
    header.extend_from_slice(&field.to_be_bytes());
    header.extend_from_slice(&[0, 0, 0, 1]);
    header
}
fn tcp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    eth(
        ETHERTYPE_IPV4,
        &v4(src, dst, PROTO_TCP, &tcp(sport, dport, flags, &[])),
    )
}
fn tcp6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    eth(
        ETHERTYPE_IPV6,
        &v6(src, dst, PROTO_TCP, 64, &tcp(sport, dport, flags, &[])),
    )
}
fn udp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16) -> Vec<u8> {
    eth(
        ETHERTYPE_IPV4,
        &v4(src, dst, PROTO_UDP, &udp(sport, dport, b"x")),
    )
}
fn udp6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16) -> Vec<u8> {
    eth(
        ETHERTYPE_IPV6,
        &v6(src, dst, PROTO_UDP, 64, &udp(sport, dport, b"x")),
    )
}
fn icmp6(src: Ipv6Addr, dst: Ipv6Addr, hop: u8, kind: u8, rest: &[u8]) -> Vec<u8> {
    eth(
        ETHERTYPE_IPV6,
        &v6(src, dst, PROTO_ICMPV6, hop, &icmp(kind, 0, rest)),
    )
}

const OUT: Direction = Direction::Outbound;
const IN: Direction = Direction::Inbound;
const ANY: Direction = Direction::Any;

fn n(name: &str) -> Option<&[u8]> {
    Some(name.as_bytes())
}

fn judge(s: &Snapshot, direction: Direction, frame: &[u8]) -> (Verdict, Reason) {
    verdict(s, IfaceClass::Guarded, direction, frame)
}
fn allow(reason: Reason) -> (Verdict, Reason) {
    (Verdict::Allow, reason)
}
fn drop(reason: Reason) -> (Verdict, Reason) {
    (Verdict::Drop, reason)
}

/// One packet of every kind the rules distinguish, for the Open, interface
/// and allocation tests.
fn corpus() -> Vec<Vec<u8>> {
    vec![
        tcp4(LOCAL, PEER, 50000, 443, SYN),
        tcp4(LOCAL, RELAY, 50000, RELAY_PORT, PSH_ACK),
        tcp6(local6(), peer6(), 50000, 443, ACK),
        udp4(LOCAL, PEER, 50000, 53),
        udp6(local6(), "ff02::fb".parse().unwrap(), MDNS_PORT, MDNS_PORT),
        icmp6(local6(), gateway6(), 64, 129, b"ping"),
        icmp6(link_local(), "ff02::2".parse().unwrap(), 255, 133, &[]),
        eth(
            ETHERTYPE_IPV4,
            &v4(LOCAL, GATEWAY, PROTO_ICMP, &icmp(0, 0, b"ping")),
        ),
        eth(ETHERTYPE_ARP, &[0, 1, 8, 0, 6, 4, 0, 1]),
        eth(0x88CC, &[0; 32]),
        vec![0x45, 0, 0],
    ]
}

#[test]
fn open_mode_allows_every_packet_on_every_interface_without_counting() {
    for frame in corpus() {
        for iface in [
            IfaceClass::Guarded,
            IfaceClass::Tunnel,
            IfaceClass::Loopback,
        ] {
            for direction in [OUT, IN, ANY] {
                assert_eq!(
                    verdict(&Snapshot::OPEN, iface, direction, &frame),
                    allow(Reason::Open)
                );
            }
        }
    }
    let gate = Gate::new();
    let counters = Counters::new();
    for frame in corpus() {
        for name in [n("en0"), n("utun3"), None] {
            assert_eq!(
                filter_packet(&gate, &counters, name, 2, &frame),
                Verdict::Allow
            );
        }
    }
    assert_eq!(counters.snapshot(), [0; COUNTED.len()]);
}

#[test]
fn tunnel_and_loopback_interfaces_allow_while_guarding_and_every_other_name_is_guarded() {
    for name in ["utun0", "utun7", "utun1234", "ipsec0", "ipsec12"] {
        assert_eq!(
            classify_interface(Some(name.as_bytes())),
            IfaceClass::Tunnel,
            "{name}"
        );
    }
    assert_eq!(classify_interface(n("lo0")), IfaceClass::Loopback);
    for name in [
        "en0",
        "en7",
        "bridge0",
        "awdl0",
        "llw0",
        "anpi0",
        "ap1",
        "pdp_ip0",
        "gif0",
        "stf0",
        "utun",
        "utunx",
        "utun12345",
        "xutun0",
        "ipsec",
        "lo",
        "loop0",
        "lo0x",
        "",
        "UTUN0",
    ] {
        assert_eq!(
            classify_interface(Some(name.as_bytes())),
            IfaceClass::Guarded,
            "{name}"
        );
    }
    assert_eq!(classify_interface(None), IfaceClass::Guarded);
    let s = armed();
    for frame in [
        tcp4(LOCAL, PEER, 50000, 443, SYN),
        icmp6(local6(), gateway6(), 64, 129, b"ping"),
        udp4(LOCAL, [224, 0, 0, 251], MDNS_PORT, MDNS_PORT),
    ] {
        for direction in [OUT, IN, ANY] {
            assert_eq!(
                verdict(&s, IfaceClass::Tunnel, direction, &frame),
                allow(Reason::TunnelIface)
            );
            assert_eq!(
                verdict(&s, IfaceClass::Loopback, direction, &frame),
                allow(Reason::LoopbackIface)
            );
            // The same packet on a physical interface drops.
            assert_eq!(judge(&s, direction, &frame).0, Verdict::Drop);
        }
    }
}

#[test]
fn guarded_interface_drops_every_tcp_segment_of_a_non_relay_flow() {
    let s = armed();
    for flags in [SYN, PSH_ACK, ACK, RST, FIN_ACK] {
        // Old sockets' keepalives (zero payload ACK), data, RSTs and FINs.
        assert_eq!(
            judge(&s, OUT, &tcp4(LOCAL, PEER, 50000, 443, flags)),
            drop(Reason::TcpOut)
        );
        assert_eq!(
            judge(&s, OUT, &tcp6(local6(), peer6(), 50000, 443, flags)),
            drop(Reason::TcpOut)
        );
        // Peer retransmissions and FINs.
        assert_eq!(
            judge(&s, IN, &tcp4(PEER, LOCAL, 443, 50000, flags)),
            drop(Reason::TcpIn)
        );
        assert_eq!(
            judge(&s, IN, &tcp6(peer6(), local6(), 443, 50000, flags)),
            drop(Reason::TcpIn)
        );
    }
    let data = eth(
        ETHERTYPE_IPV4,
        &v4(LOCAL, PEER, PROTO_TCP, &tcp(50000, 80, PSH_ACK, &[7; 100])),
    );
    assert_eq!(judge(&s, OUT, &data), drop(Reason::TcpOut));
}

#[test]
fn relay_tcp_is_allowed_both_ways_and_only_on_its_address_and_port() {
    let s = armed();
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&s, IN, &tcp4(RELAY, LOCAL, RELAY_PORT, 50000, ACK)),
        allow(Reason::Relay)
    );
    // The relay's address on another port, another host on 443.
    for port in [80, 7, 8080, 444] {
        assert_eq!(
            judge(&s, OUT, &tcp4(LOCAL, RELAY, 50000, port, SYN)),
            drop(Reason::TcpOut),
            "{port}"
        );
        assert_eq!(
            judge(&s, IN, &tcp4(RELAY, LOCAL, port, 50000, ACK)),
            drop(Reason::TcpIn),
            "{port}"
        );
    }
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, PEER, 50000, RELAY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
    // The orientation matters: outbound from the relay port is not the relay.
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, PEER, RELAY_PORT, 50000, ACK)),
        drop(Reason::TcpOut)
    );
    assert_eq!(
        judge(&s, IN, &tcp4(PEER, LOCAL, 50000, RELAY_PORT, ACK)),
        drop(Reason::TcpIn)
    );
    // An IPv6 relay.
    let s6 = armed6();
    assert_eq!(
        judge(&s6, OUT, &tcp6(local6(), relay6(), 50000, RELAY_PORT, SYN)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&s6, IN, &tcp6(relay6(), local6(), RELAY_PORT, 50000, ACK)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&s6, OUT, &tcp6(local6(), relay6(), 50000, 80, SYN)),
        drop(Reason::TcpOut)
    );
    assert_eq!(
        judge(&s6, OUT, &tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
    // UDP to the relay only when the carrier allows UDP.
    assert_eq!(
        judge(&s, OUT, &udp4(LOCAL, RELAY, 50000, RELAY_PORT)),
        drop(Reason::Udp)
    );
    let udp_allowed = guarding(Some(relay4()), true);
    assert_eq!(
        judge(&udp_allowed, OUT, &udp4(LOCAL, RELAY, 50000, RELAY_PORT)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&udp_allowed, IN, &udp4(RELAY, LOCAL, RELAY_PORT, 50000)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&udp_allowed, OUT, &udp4(LOCAL, PEER, 50000, RELAY_PORT)),
        drop(Reason::Udp)
    );
    // UDP to the authority port is never allowed.
    assert_eq!(
        judge(
            &udp_allowed,
            OUT,
            &udp4(LOCAL, RELAY, 50000, AUTHORITY_PORT)
        ),
        drop(Reason::Udp)
    );
    // No relay armed: the relay's traffic drops too.
    let bare = guarding(None, false);
    assert_eq!(
        judge(&bare, OUT, &tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
}

#[test]
fn authority_tcp_drops_while_guarding_since_v31() {
    // v31 (S23b): replaces S20b's `authority_tcp_is_allowed_only_while_armed
    // _with_that_authority`. The authority's own port on the relay host (the
    // 21 SYNs of window-v30-ifswitch-r3) and an authority on its own host
    // are ordinary TCP now, in both directions; the relay port still passes.
    let s = armed();
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, RELAY, 50001, AUTHORITY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
    assert_eq!(
        judge(&s, IN, &tcp4(RELAY, LOCAL, AUTHORITY_PORT, 50001, ACK)),
        drop(Reason::TcpIn)
    );
    assert_eq!(
        judge(&s, ANY, &tcp4(LOCAL, RELAY, 50001, AUTHORITY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, RELAY, 50001, RELAY_PORT, SYN)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, PEER, 50001, AUTHORITY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
    let s6 = armed6();
    assert_eq!(
        judge(
            &s6,
            OUT,
            &tcp6(local6(), relay6(), 50001, AUTHORITY_PORT, SYN)
        ),
        drop(Reason::TcpOut)
    );
    // The gate's dial check: only the relay's own tuple, and nothing while
    // a torn read guards.
    let authority: SocketAddr = "203.0.113.10:9445".parse().unwrap();
    let relay: SocketAddr = "203.0.113.10:443".parse().unwrap();
    assert!(s.dial_refused(authority));
    assert!(!s.dial_refused(relay));
    assert!(!s.dial_refused("[::ffff:203.0.113.10]:443".parse().unwrap()));
    assert!(s.dial_refused("198.51.100.9:443".parse().unwrap()));
    assert!(Snapshot::FAIL_CLOSED.dial_refused(relay));
    assert!(!Snapshot::OPEN.dial_refused(authority));
    let gate = Gate::new();
    assert!(!gate.dial_refused(authority), "open: a provider start");
    let token = gate.arm(Some(relay4()), false);
    assert!(gate.dial_refused(authority));
    assert!(!gate.dial_refused(relay));
    assert!(gate.disarm(token));
    assert!(!gate.dial_refused(authority));
}

#[test]
fn dhcp_client_traffic_is_allowed_only_in_its_own_direction() {
    let s = armed();
    let broadcast = [255, 255, 255, 255];
    assert_eq!(
        judge(&s, OUT, &udp4([0, 0, 0, 0], broadcast, 68, 67)),
        allow(Reason::Dhcp4)
    );
    assert_eq!(
        judge(&s, IN, &udp4(GATEWAY, broadcast, 67, 68)),
        allow(Reason::Dhcp4)
    );
    // Reversed ports in either direction, or DHCPv6 ports over IPv4.
    assert_eq!(
        judge(&s, OUT, &udp4(LOCAL, GATEWAY, 67, 68)),
        drop(Reason::Udp)
    );
    assert_eq!(
        judge(&s, IN, &udp4(GATEWAY, LOCAL, 68, 67)),
        drop(Reason::Udp)
    );
    assert_eq!(
        judge(&s, OUT, &udp4(LOCAL, GATEWAY, 546, 547)),
        drop(Reason::Udp)
    );
    assert_eq!(
        judge(&s, OUT, &udp4(LOCAL, GATEWAY, 68, 68)),
        drop(Reason::Udp)
    );
    let servers: Ipv6Addr = "ff02::1:2".parse().unwrap();
    assert_eq!(
        judge(&s, OUT, &udp6(link_local(), servers, 546, 547)),
        allow(Reason::Dhcp6)
    );
    assert_eq!(
        judge(&s, IN, &udp6(gateway6(), link_local(), 547, 546)),
        allow(Reason::Dhcp6)
    );
    assert_eq!(
        judge(&s, OUT, &udp6(link_local(), gateway6(), 547, 546)),
        drop(Reason::Udp)
    );
    assert_eq!(
        judge(&s, IN, &udp6(gateway6(), link_local(), 546, 547)),
        drop(Reason::Udp)
    );
    assert_eq!(
        judge(&s, OUT, &udp6(link_local(), servers, 68, 67)),
        drop(Reason::Udp)
    );
}

#[test]
fn neighbour_discovery_and_mld_are_allowed_only_with_their_hop_limits() {
    let s = armed();
    let routers: Ipv6Addr = "ff02::2".parse().unwrap();
    let solicited: Ipv6Addr = "ff02::1:ff00:1".parse().unwrap();
    let unspecified = Ipv6Addr::UNSPECIFIED;
    for (src, dst, kind) in [
        (link_local(), routers, 133),
        (gateway6(), link_local(), 134),
        (link_local(), solicited, 135),
        (unspecified, solicited, 135), // DAD
        (link_local(), gateway6(), 136),
        (gateway6(), link_local(), 137),
    ] {
        for direction in [OUT, IN] {
            assert_eq!(
                judge(&s, direction, &icmp6(src, dst, 255, kind, &[0; 16])),
                allow(Reason::Nd),
                "{kind}"
            );
            assert_eq!(
                judge(&s, direction, &icmp6(src, dst, 64, kind, &[0; 16])),
                drop(Reason::Icmp6Other),
                "{kind} hop 64"
            );
            assert_eq!(
                judge(&s, direction, &icmp6(src, dst, 254, kind, &[0; 16])),
                drop(Reason::Icmp6Other),
                "{kind} hop 254"
            );
        }
    }
    // MLDv2 report behind a hop-by-hop router-alert header.
    let mldv2: Ipv6Addr = "ff02::16".parse().unwrap();
    let mut rest = ext(PROTO_ICMPV6, 0);
    rest[2..8].copy_from_slice(&[0x05, 0x02, 0, 0, 0x01, 0x00]);
    rest.extend_from_slice(&icmp(143, 0, &[0; 4]));
    let report = |src: Ipv6Addr, hop: u8| eth(ETHERTYPE_IPV6, &v6(src, mldv2, 0, hop, &rest));
    assert_eq!(judge(&s, OUT, &report(link_local(), 1)), allow(Reason::Mld));
    assert_eq!(judge(&s, OUT, &report(unspecified, 1)), allow(Reason::Mld));
    for kind in [130, 131, 132] {
        assert_eq!(
            judge(&s, IN, &icmp6(gateway6(), mldv2, 1, kind, &[0; 16])),
            allow(Reason::Mld),
            "{kind}"
        );
    }
    // A global source or a hop limit of 2 is not MLD.
    assert_eq!(
        judge(&s, OUT, &report(local6(), 1)),
        drop(Reason::Icmp6Other)
    );
    assert_eq!(
        judge(&s, OUT, &report(link_local(), 2)),
        drop(Reason::Icmp6Other)
    );
    // Just outside fe80::/10.
    assert_eq!(
        judge(&s, OUT, &report("fec0::1".parse().unwrap(), 1)),
        drop(Reason::Icmp6Other)
    );
    assert_eq!(
        judge(&s, OUT, &report("febf::1".parse().unwrap(), 1)),
        allow(Reason::Mld)
    );
}

/// The first bytes of one of our packets, as an ICMP error quotes it.
fn quoted4(dst: [u8; 4], proto: u8, dport: u16) -> Vec<u8> {
    let l4 = if proto == PROTO_UDP {
        udp(50000, dport, &[])
    } else {
        tcp(50000, dport, ACK, &[])
    };
    v4(LOCAL, dst, proto, &l4)[..28].to_vec()
}
fn quoted6(dst: Ipv6Addr, proto: u8, dport: u16) -> Vec<u8> {
    let l4 = if proto == PROTO_UDP {
        udp(50000, dport, &[])
    } else {
        tcp(50000, dport, ACK, &[])
    };
    v6(local6(), dst, proto, 64, &l4)[..48].to_vec()
}

#[test]
fn icmpv6_echo_and_errors_drop_unless_an_inbound_error_quotes_the_relay() {
    let s6 = armed6();
    let s = armed();
    // Echo to and from the LAN gateway (the S20 residue).
    assert_eq!(
        judge(&s, OUT, &icmp6(local6(), gateway6(), 64, 129, b"ping")),
        drop(Reason::Icmp6Echo)
    );
    assert_eq!(
        judge(&s, IN, &icmp6(gateway6(), local6(), 64, 128, b"ping")),
        drop(Reason::Icmp6Echo)
    );
    // A port unreachable for a closed QUIC socket.
    let quic = quoted6(local6(), PROTO_UDP, 51000);
    assert_eq!(
        judge(&s, OUT, &icmp6(local6(), peer6(), 64, 1, &quic)),
        drop(Reason::Icmp6Error)
    );
    // Packet Too Big for our relay flow.
    let relay_flow = quoted6(relay6(), PROTO_TCP, RELAY_PORT);
    assert_eq!(
        judge(&s6, IN, &icmp6(peer6(), local6(), 64, 2, &relay_flow)),
        allow(Reason::RelayIcmpError)
    );
    for kind in [1, 3, 4] {
        assert_eq!(
            judge(&s6, IN, &icmp6(peer6(), local6(), 64, kind, &relay_flow)),
            allow(Reason::RelayIcmpError),
            "{kind}"
        );
    }
    // v31: an error quoting a flow to the authority's own port quotes no
    // allowed flow any more (S20b allowed it).
    let authority_flow = quoted6(relay6(), PROTO_TCP, AUTHORITY_PORT);
    assert_eq!(
        judge(&s6, IN, &icmp6(peer6(), local6(), 64, 2, &authority_flow)),
        drop(Reason::Icmp6Error)
    );
    // Outbound, another flow, another port or a UDP flow to the relay.
    assert_eq!(
        judge(&s6, OUT, &icmp6(local6(), peer6(), 64, 2, &relay_flow)),
        drop(Reason::Icmp6Error)
    );
    for quoted in [
        quoted6(peer6(), PROTO_TCP, RELAY_PORT),
        quoted6(relay6(), PROTO_TCP, 80),
        quoted6(relay6(), PROTO_UDP, RELAY_PORT),
        quoted6(relay6(), PROTO_TCP, RELAY_PORT)[..40].to_vec(),
        quoted4(RELAY, PROTO_TCP, RELAY_PORT),
    ] {
        assert_eq!(
            judge(&s6, IN, &icmp6(peer6(), local6(), 64, 2, &quoted)),
            drop(Reason::Icmp6Error)
        );
    }
    // Other ICMPv6 (node information, router renumbering) drops.
    assert_eq!(
        judge(&s, OUT, &icmp6(local6(), peer6(), 64, 139, &[0; 8])),
        drop(Reason::Icmp6Other)
    );
    // An empty ICMPv6 body is malformed.
    let empty = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), peer6(), PROTO_ICMPV6, 64, &[]),
    );
    assert_eq!(judge(&s, OUT, &empty), drop(Reason::Malformed));
}

#[test]
fn icmpv4_igmp_and_mdns_drop_unless_an_inbound_error_quotes_the_relay() {
    let s = armed();
    let icmp4 = |src, dst, kind, code, rest: &[u8]| {
        eth(
            ETHERTYPE_IPV4,
            &v4(src, dst, PROTO_ICMP, &icmp(kind, code, rest)),
        )
    };
    let relay_flow = quoted4(RELAY, PROTO_TCP, RELAY_PORT);
    // Fragmentation needed and time exceeded for our relay flow.
    assert_eq!(
        judge(&s, IN, &icmp4(PEER, LOCAL, 3, 4, &relay_flow)),
        allow(Reason::RelayIcmpError)
    );
    assert_eq!(
        judge(&s, IN, &icmp4(PEER, LOCAL, 11, 0, &relay_flow)),
        allow(Reason::RelayIcmpError)
    );
    // v31: the authority's own port is no allowed flow any more.
    assert_eq!(
        judge(
            &s,
            IN,
            &icmp4(
                PEER,
                LOCAL,
                3,
                4,
                &quoted4(RELAY, PROTO_TCP, AUTHORITY_PORT)
            )
        ),
        drop(Reason::Icmp4In)
    );
    // Another type, another flow, or outbound.
    assert_eq!(
        judge(&s, IN, &icmp4(PEER, LOCAL, 5, 0, &relay_flow)),
        drop(Reason::Icmp4In)
    );
    for quoted in [
        quoted4(PEER, PROTO_TCP, RELAY_PORT),
        quoted4(RELAY, PROTO_TCP, 80),
        quoted4(RELAY, PROTO_UDP, RELAY_PORT),
        quoted4(RELAY, PROTO_TCP, RELAY_PORT)[..22].to_vec(),
        quoted6(relay6(), PROTO_TCP, RELAY_PORT),
    ] {
        assert_eq!(
            judge(&s, IN, &icmp4(PEER, LOCAL, 3, 4, &quoted)),
            drop(Reason::Icmp4In)
        );
    }
    assert_eq!(
        judge(&s, OUT, &icmp4(LOCAL, PEER, 3, 3, &relay_flow)),
        drop(Reason::Icmp4Out)
    );
    assert_eq!(
        judge(&s, OUT, &icmp4(LOCAL, GATEWAY, 0, 0, b"ping")),
        drop(Reason::Icmp4Out)
    );
    assert_eq!(
        judge(&s, IN, &icmp4(GATEWAY, LOCAL, 8, 0, b"ping")),
        drop(Reason::Icmp4In)
    );
    // With UDP allowed, an error quoting the UDP relay flow is allowed.
    let udp_allowed = guarding(Some(relay4()), true);
    assert_eq!(
        judge(
            &udp_allowed,
            IN,
            &icmp4(PEER, LOCAL, 3, 4, &quoted4(RELAY, PROTO_UDP, RELAY_PORT))
        ),
        allow(Reason::RelayIcmpError)
    );
    let igmp = eth(
        ETHERTYPE_IPV4,
        &v4(
            LOCAL,
            [224, 0, 0, 22],
            PROTO_IGMP,
            &[0x22, 0, 0, 0, 0, 0, 0, 0],
        ),
    );
    assert_eq!(judge(&s, OUT, &igmp), drop(Reason::Igmp));
    assert_eq!(
        judge(
            &s,
            OUT,
            &udp4(LOCAL, [224, 0, 0, 251], MDNS_PORT, MDNS_PORT)
        ),
        drop(Reason::Mdns)
    );
    assert_eq!(
        judge(&s, IN, &udp4(PEER, LOCAL, MDNS_PORT, 50000)),
        drop(Reason::Mdns)
    );
    assert_eq!(
        judge(
            &s,
            OUT,
            &udp6(
                link_local(),
                "ff02::fb".parse().unwrap(),
                MDNS_PORT,
                MDNS_PORT
            )
        ),
        drop(Reason::Mdns)
    );
    // ESP, an IPv4 ICMP type number in IPv6, and IGMP's number in IPv6.
    let esp = eth(ETHERTYPE_IPV4, &v4(LOCAL, PEER, 50, &[0; 16]));
    assert_eq!(judge(&s, OUT, &esp), drop(Reason::OtherProto));
    let icmp_in_v6 = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), peer6(), PROTO_ICMP, 64, &icmp(8, 0, &[])),
    );
    assert_eq!(judge(&s, OUT, &icmp_in_v6), drop(Reason::OtherProto));
    let igmp_in_v6 = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), peer6(), PROTO_IGMP, 64, &[0; 8]),
    );
    assert_eq!(judge(&s, OUT, &igmp_in_v6), drop(Reason::OtherProto));
    let icmpv6_in_v4 = eth(
        ETHERTYPE_IPV4,
        &v4(LOCAL, PEER, PROTO_ICMPV6, &icmp(128, 0, &[])),
    );
    assert_eq!(judge(&s, OUT, &icmpv6_in_v4), drop(Reason::OtherProto));
}

#[test]
fn later_fragments_are_judged_by_their_address_pair_and_protocol() {
    let s = armed();
    let later = |src, dst, proto| {
        eth(
            ETHERTYPE_IPV4,
            &v4_full(src, dst, proto, 64, 185, &[0xaa; 24]),
        )
    };
    assert_eq!(
        judge(&s, OUT, &later(LOCAL, RELAY, PROTO_TCP)),
        allow(Reason::RelayFragment)
    );
    assert_eq!(
        judge(&s, IN, &later(RELAY, LOCAL, PROTO_TCP)),
        allow(Reason::RelayFragment)
    );
    assert_eq!(
        judge(&s, OUT, &later(LOCAL, PEER, PROTO_TCP)),
        drop(Reason::Fragment)
    );
    assert_eq!(
        judge(&s, IN, &later(LOCAL, RELAY, PROTO_TCP)),
        drop(Reason::Fragment)
    );
    assert_eq!(
        judge(&s, OUT, &later(LOCAL, RELAY, PROTO_UDP)),
        drop(Reason::Fragment)
    );
    assert_eq!(
        judge(&s, OUT, &later(LOCAL, RELAY, PROTO_ICMP)),
        drop(Reason::Fragment)
    );
    let udp_allowed = guarding(Some(relay4()), true);
    assert_eq!(
        judge(&udp_allowed, OUT, &later(LOCAL, RELAY, PROTO_UDP)),
        allow(Reason::RelayFragment)
    );
    // v31: an authority on its own host is no armed address pair any more
    // (S20b allowed its TCP fragments): neither TCP nor UDP passes.
    let elsewhere = guarding(Some(relay4()), true);
    assert_eq!(
        judge(&elsewhere, OUT, &later(LOCAL, PEER, PROTO_TCP)),
        drop(Reason::Fragment)
    );
    assert_eq!(
        judge(&elsewhere, OUT, &later(LOCAL, PEER, PROTO_UDP)),
        drop(Reason::Fragment)
    );
    // A first fragment (offset 0, more fragments) carries ports: normal rules.
    let first = eth(
        ETHERTYPE_IPV4,
        &v4_full(
            LOCAL,
            PEER,
            PROTO_TCP,
            64,
            0x2000,
            &tcp(50000, 443, ACK, &[1; 8]),
        ),
    );
    assert_eq!(judge(&s, OUT, &first), drop(Reason::TcpOut));
    let first_relay = eth(
        ETHERTYPE_IPV4,
        &v4_full(
            LOCAL,
            RELAY,
            PROTO_TCP,
            64,
            0x2000,
            &tcp(50000, RELAY_PORT, ACK, &[1; 8]),
        ),
    );
    assert_eq!(judge(&s, OUT, &first_relay), allow(Reason::Relay));
    // IPv6 Fragment header with a non-zero offset.
    let s6 = armed6();
    let later6 = |src, dst, next| {
        let mut rest = frag6(next, 100, true);
        rest.extend_from_slice(&[0xbb; 24]);
        eth(ETHERTYPE_IPV6, &v6(src, dst, 44, 64, &rest))
    };
    assert_eq!(
        judge(&s6, OUT, &later6(local6(), relay6(), PROTO_TCP)),
        allow(Reason::RelayFragment)
    );
    assert_eq!(
        judge(&s6, IN, &later6(relay6(), local6(), PROTO_TCP)),
        allow(Reason::RelayFragment)
    );
    assert_eq!(
        judge(&s6, OUT, &later6(local6(), peer6(), PROTO_TCP)),
        drop(Reason::Fragment)
    );
    // An atomic IPv6 fragment (offset 0) is judged by its upper layer.
    let mut atomic = frag6(PROTO_TCP, 0, false);
    atomic.extend_from_slice(&tcp(50000, RELAY_PORT, ACK, &[]));
    assert_eq!(
        judge(
            &s6,
            OUT,
            &eth(ETHERTYPE_IPV6, &v6(local6(), relay6(), 44, 64, &atomic))
        ),
        allow(Reason::Relay)
    );
    let mut atomic_peer = frag6(PROTO_TCP, 0, false);
    atomic_peer.extend_from_slice(&tcp(50000, RELAY_PORT, ACK, &[]));
    assert_eq!(
        judge(
            &s6,
            OUT,
            &eth(ETHERTYPE_IPV6, &v6(local6(), peer6(), 44, 64, &atomic_peer))
        ),
        drop(Reason::TcpOut)
    );
}

/// `count` extension headers (hop-by-hop first, then destination options)
/// before a TCP segment to `dst`.
fn chained(count: usize, dst: Ipv6Addr) -> Vec<u8> {
    let kinds: Vec<u8> = (0..count).map(|i| if i == 0 { 0 } else { 60 }).collect();
    let mut rest = Vec::new();
    for (i, _) in kinds.iter().enumerate() {
        let next = kinds.get(i + 1).copied().unwrap_or(PROTO_TCP);
        rest.extend_from_slice(&ext(next, 0));
    }
    rest.extend_from_slice(&tcp(50000, RELAY_PORT, ACK, &[]));
    let first = kinds.first().copied().unwrap_or(PROTO_TCP);
    eth(ETHERTYPE_IPV6, &v6(local6(), dst, first, 64, &rest))
}

#[test]
fn the_ipv6_extension_walk_is_bounded_and_length_checked() {
    let s6 = armed6();
    for count in 0..=MAX_EXTENSION_HEADERS {
        assert_eq!(
            judge(&s6, OUT, &chained(count, relay6())),
            allow(Reason::Relay),
            "{count}"
        );
        assert_eq!(
            judge(&s6, OUT, &chained(count, peer6())),
            drop(Reason::TcpOut),
            "{count}"
        );
    }
    assert_eq!(
        judge(&s6, OUT, &chained(MAX_EXTENSION_HEADERS + 1, relay6())),
        drop(Reason::Malformed)
    );
    // A routing header whose length runs past the payload.
    let mut rest = ext(PROTO_TCP, 0);
    rest[1] = 5;
    rest.extend_from_slice(&tcp(50000, RELAY_PORT, ACK, &[]));
    assert_eq!(
        judge(
            &s6,
            OUT,
            &eth(ETHERTYPE_IPV6, &v6(local6(), relay6(), 43, 64, &rest))
        ),
        drop(Reason::Malformed)
    );
    // A fragment header cut short.
    let short = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), relay6(), 44, 64, &[PROTO_TCP, 0, 0]),
    );
    assert_eq!(judge(&s6, OUT, &short), drop(Reason::Malformed));
    // A TCP header without its ports, IPv4 and IPv6.
    let cut4 = eth(ETHERTYPE_IPV4, &v4(LOCAL, RELAY, PROTO_TCP, &[1, 187, 0]));
    assert_eq!(judge(&armed(), OUT, &cut4), drop(Reason::Malformed));
    let cut6 = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), relay6(), PROTO_TCP, 64, &[1, 187]),
    );
    assert_eq!(judge(&s6, OUT, &cut6), drop(Reason::Malformed));
    let cut_udp = eth(ETHERTYPE_IPV4, &v4(LOCAL, RELAY, PROTO_UDP, &[0, 68]));
    assert_eq!(judge(&armed(), OUT, &cut_udp), drop(Reason::Malformed));
    let empty_icmp = eth(ETHERTYPE_IPV4, &v4(LOCAL, RELAY, PROTO_ICMP, &[]));
    assert_eq!(judge(&armed(), IN, &empty_icmp), drop(Reason::Malformed));
}

#[test]
fn framing_is_ethernet_vlan_or_exact_raw_ip_and_anything_else_drops() {
    let s = armed();
    let relay = v4(LOCAL, RELAY, PROTO_TCP, &tcp(50000, RELAY_PORT, ACK, &[]));
    let other = v4(LOCAL, PEER, PROTO_TCP, &tcp(50000, 443, ACK, &[]));
    // 802.1Q tagged.
    assert_eq!(
        judge(&s, OUT, &vlan(ETHERTYPE_IPV4, &relay)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&s, OUT, &vlan(ETHERTYPE_IPV4, &other)),
        drop(Reason::TcpOut)
    );
    // Raw IP (no link-layer header), IPv4 and IPv6.
    assert_eq!(judge(&s, OUT, &relay), allow(Reason::Relay));
    assert_eq!(judge(&s, OUT, &other), drop(Reason::TcpOut));
    let raw6 = v6(
        relay6(),
        local6(),
        PROTO_TCP,
        64,
        &tcp(RELAY_PORT, 50000, ACK, &[]),
    );
    assert_eq!(judge(&armed6(), IN, &raw6), allow(Reason::Relay));
    // Ethernet padding after a short IP packet is allowed; raw IP must be exact.
    let mut padded = eth(ETHERTYPE_IPV4, &relay);
    padded.extend_from_slice(&[0; 6]);
    assert_eq!(judge(&s, OUT, &padded), allow(Reason::Relay));
    let mut trailing = relay.clone();
    trailing.push(0);
    // Not exact, so not raw IP; read as Ethernet its "ethertype" is the
    // source address: an unknown non-IP frame.
    assert_eq!(judge(&s, OUT, &trailing), drop(Reason::NonIp));
    // Truncated Ethernet, IHL < 5, total length past the frame, version 5.
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_IPV4, &relay)[..13]),
        drop(Reason::Malformed)
    );
    let mut ihl = relay.clone();
    ihl[0] = 0x44;
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_IPV4, &ihl)),
        drop(Reason::Malformed)
    );
    let mut long = relay.clone();
    long[3] = long[3].wrapping_add(1);
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_IPV4, &long)),
        drop(Reason::Malformed)
    );
    let mut version = relay.clone();
    version[0] = 0x55;
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_IPV4, &version)),
        drop(Reason::Malformed)
    );
    // An IPv6 ethertype carrying IPv4 is not consistent.
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_IPV6, &relay)),
        drop(Reason::Malformed)
    );
    let mut long6 = raw6.clone();
    long6[5] = long6[5].wrapping_add(1);
    assert_eq!(
        judge(&armed6(), IN, &eth(ETHERTYPE_IPV6, &long6)),
        drop(Reason::Malformed)
    );
    assert_eq!(judge(&s, OUT, &[]), drop(Reason::Malformed));
    assert_eq!(judge(&s, OUT, &[0x45]), drop(Reason::Malformed));
    // ARP and EAPOL with plausible headers are link control; LLDP is not.
    let arp = eth(ETHERTYPE_ARP, &[0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 1]);
    let eapol = eth(ETHERTYPE_EAPOL, &[2, 3, 0, 95]);
    for direction in [OUT, IN, ANY] {
        assert_eq!(judge(&s, direction, &arp), allow(Reason::LinkControl));
        assert_eq!(judge(&s, direction, &eapol), allow(Reason::LinkControl));
        assert_eq!(
            judge(&s, direction, &eth(0x88CC, &[0; 32])),
            drop(Reason::NonIp)
        );
    }
    assert_eq!(
        judge(&s, OUT, &vlan(ETHERTYPE_ARP, &[0, 1, 8, 0, 6, 4, 0, 1])),
        allow(Reason::LinkControl)
    );
    // An ARP or EAPOL ethertype with an implausible header drops.
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_ARP, &[0, 6, 8, 0, 6, 4])),
        drop(Reason::Malformed)
    );
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_EAPOL, &[9, 0])),
        drop(Reason::Malformed)
    );
    assert_eq!(
        judge(&s, OUT, &eth(ETHERTYPE_EAPOL, &[2, 9])),
        drop(Reason::Malformed)
    );
    // A truncated VLAN tag.
    assert_eq!(
        judge(&s, OUT, &vlan(ETHERTYPE_IPV4, &[])[..16]),
        drop(Reason::NonIp)
    );
}

#[test]
fn direction_any_allows_a_relay_packet_in_either_orientation_only() {
    let s = armed();
    assert_eq!(
        judge(&s, ANY, &tcp4(LOCAL, RELAY, 50000, RELAY_PORT, ACK)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&s, ANY, &tcp4(RELAY, LOCAL, RELAY_PORT, 50000, ACK)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&s, ANY, &tcp4(LOCAL, PEER, 50000, 443, ACK)),
        drop(Reason::TcpOut)
    );
    assert_eq!(
        judge(&s, ANY, &udp4(GATEWAY, [255; 4], 67, 68)),
        allow(Reason::Dhcp4)
    );
    // An unknown raw direction is judged as Any.
    assert_eq!(Direction::from_raw(0), Direction::Any);
    assert_eq!(Direction::from_raw(1), Direction::Inbound);
    assert_eq!(Direction::from_raw(2), Direction::Outbound);
    assert_eq!(Direction::from_raw(3), Direction::Any);
    assert_eq!(Direction::from_raw(-1), Direction::Any);
    assert_eq!(Verdict::Allow.raw(), 0);
    assert_eq!(Verdict::Drop.raw(), 1);
}

#[test]
fn a_raw_ip_packet_whose_source_reads_as_arp_or_eapol_is_judged_as_ip() {
    let s = armed();
    // Raw IPv4 from 136.142.1.5: bytes 12-15 are 88 8e 01 05, a plausible
    // EAPOL ethertype and header when read as Ethernet.
    let host = [136, 142, 1, 5];
    let eapol_like = v4(host, PEER, PROTO_TCP, &tcp(50000, 443, ACK, &[]));
    assert_eq!(eapol_like[12..16], [0x88, 0x8e, 0x01, 0x05]);
    assert_eq!(
        frame(&eapol_like),
        Frame::LinkControl,
        "the Ethernet reading"
    );
    assert_eq!(judge(&s, OUT, &eapol_like), drop(Reason::TcpOut));
    assert_eq!(judge(&s, ANY, &eapol_like), drop(Reason::TcpOut));
    let inbound = v4(host, LOCAL, PROTO_TCP, &tcp(443, 50000, ACK, &[]));
    assert_eq!(judge(&s, IN, &inbound), drop(Reason::TcpIn));
    // ARP-like: source 8.6.0.1 and destination 8.0.6.4.
    let arp_like = v4([8, 6, 0, 1], [8, 0, 6, 4], PROTO_UDP, &udp(50000, 53, b"x"));
    assert_eq!(frame(&arp_like), Frame::LinkControl);
    assert_eq!(judge(&s, OUT, &arp_like), drop(Reason::Udp));
    // IPv6: source bytes 4-7 are 88 8e 01 00.
    let src6: Ipv6Addr = "2001:db8:888e:100::1".parse().unwrap();
    let v6_like = v6(src6, peer6(), PROTO_TCP, 64, &tcp(50000, 443, ACK, &[]));
    assert_eq!(frame(&v6_like), Frame::LinkControl);
    assert_eq!(judge(&armed6(), OUT, &v6_like), drop(Reason::TcpOut));
    // Through the counted entry point the IP reason is what is counted.
    let gate = Gate::new();
    let counters = Counters::new();
    gate.arm(Some(relay4()), false);
    assert_eq!(
        filter_packet(&gate, &counters, n("gif0"), 2, &eapol_like),
        Verdict::Drop
    );
    let values = counters.snapshot();
    assert_eq!(values[Reason::TcpOut.index().unwrap()], 1);
    assert_eq!(values[Reason::LinkControl.index().unwrap()], 0);
    // Relay traffic from such an address is still the relay.
    let relay_there = guarding(
        Some(peer(IpAddr::V4(Ipv4Addr::from(host)), RELAY_PORT)),
        false,
    );
    let from_relay = v4(host, LOCAL, PROTO_TCP, &tcp(RELAY_PORT, 50000, ACK, &[]));
    assert_eq!(judge(&relay_there, IN, &from_relay), allow(Reason::Relay));
    // Real Ethernet ARP and EAPOL frames stay link control.
    assert_eq!(judge(&s, OUT, &arp_frame()), allow(Reason::LinkControl));
    assert_eq!(
        judge(&s, IN, &eth(ETHERTYPE_EAPOL, &[2, 3, 0, 95])),
        allow(Reason::LinkControl)
    );
    // Not exact raw IP (one trailing byte): the Ethernet reading stands.
    let mut trailing = eapol_like.clone();
    trailing.push(0);
    assert_eq!(judge(&s, OUT, &trailing), allow(Reason::LinkControl));
}

fn v4_peer(octets: [u8; 4], port: u16) -> Option<Peer> {
    Some(peer(IpAddr::V4(Ipv4Addr::from(octets)), port))
}

#[test]
fn the_gate_issues_a_token_per_arm_and_only_that_token_opens_it() {
    let gate = Gate::new();
    assert_eq!(gate.snapshot(), (Snapshot::OPEN, false));
    assert!(!gate.disarm(ArmToken(0)), "nothing armed");
    assert!(!gate.disarm(ArmToken(1)), "nothing armed");
    let first = gate.arm(Some(relay4()), false);
    assert_eq!(first.get(), 1);
    let (s, torn) = gate.snapshot();
    assert!(!torn);
    assert_eq!(s, guarding(Some(relay4()), false).with_token(1));
    // A token never issued (stale or future) leaves it guarding.
    assert!(!gate.disarm(ArmToken(0)));
    assert!(!gate.disarm(ArmToken(2)));
    assert_eq!(gate.snapshot().0.mode, Mode::Guarding);
    // A re-arm replaces the endpoint (the old relay drops) and issues a
    // new token.
    let second = gate.arm(v4_peer(PEER, RELAY_PORT), true);
    assert_eq!(second.get(), 2);
    let (s, _) = gate.snapshot();
    assert_eq!(s.token, 2);
    assert_eq!(s.relays, PeerSet::one(v4_peer(PEER, RELAY_PORT)));
    assert!(s.udp_relay);
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, PEER, 50000, RELAY_PORT, SYN)),
        allow(Reason::Relay)
    );
    assert!(
        !gate.disarm(first),
        "the older arm cannot open the newer one"
    );
    assert!(gate.disarm(second));
    assert_eq!(gate.snapshot(), (Snapshot::OPEN, false));
    assert!(!gate.disarm(second), "already open");
    // Tokens never repeat after an open: the next arm is not opened by
    // any token issued before it.
    let v6_relay = Some(peer(IpAddr::V6(relay6()), RELAY_PORT));
    let third = gate.arm(v6_relay, false);
    assert_eq!(third.get(), 3);
    assert!(!gate.disarm(first) && !gate.disarm(second));
    // IPv6 endpoints round-trip through the cells.
    assert_eq!(gate.snapshot().0.relays, PeerSet::one(v6_relay));
    assert_eq!(gate.snapshot().0.mode, Mode::Guarding);
    assert!(gate.disarm(third));
}

#[test]
fn concurrent_arms_store_the_newest_token_issued() {
    // Tokens are issued inside the write section: whichever arm wrote last
    // holds the highest token, and only it opens the gate.
    let gate = Arc::new(Gate::new());
    let workers: Vec<_> = (0..4)
        .map(|_| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                (0..2_000)
                    .map(|_| gate.arm(Some(relay4()), false).get())
                    .max()
                    .unwrap()
            })
        })
        .collect();
    let newest = workers
        .into_iter()
        .map(|w| w.join().unwrap())
        .max()
        .unwrap();
    assert_eq!(newest, 8_000);
    assert_eq!(gate.snapshot().0.token, newest);
    assert!(!gate.disarm(ArmToken(newest - 1)));
    assert!(gate.disarm(ArmToken(newest)));
}

impl Snapshot {
    fn with_token(mut self, token: u64) -> Self {
        self.token = token;
        self
    }
}

#[test]
fn a_reader_never_sees_a_mixed_endpoint_and_a_torn_read_fails_closed() {
    let gate = Arc::new(Gate::new());
    // Two endpoints that differ in every address word and in the port.
    let a = Some(peer(
        IpAddr::V6("2001:db8:aaaa:aaaa:aaaa:aaaa:aaaa:aaaa".parse().unwrap()),
        1111,
    ));
    let b = Some(peer(
        IpAddr::V6("2001:db8:bbbb:bbbb:bbbb:bbbb:bbbb:bbbb".parse().unwrap()),
        2222,
    ));
    gate.arm(a, false);
    let writers: Vec<_> = (0..2)
        .map(|w| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                for i in 0..20_000u64 {
                    let (p, udp) = if (i + w) % 2 == 0 {
                        (a, false)
                    } else {
                        (b, true)
                    };
                    gate.arm(p, udp);
                }
            })
        })
        .collect();
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                let mut torn = 0u64;
                for _ in 0..40_000 {
                    let (s, was_torn) = gate.snapshot();
                    if was_torn {
                        assert_eq!(s, Snapshot::FAIL_CLOSED);
                        torn += 1;
                        continue;
                    }
                    let consistent = s.token != 0
                        && ((s.relays == PeerSet::one(a) && !s.udp_relay)
                            || (s.relays == PeerSet::one(b) && s.udp_relay));
                    assert!(consistent, "mixed snapshot {s:?}");
                }
                torn
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    for reader in readers {
        reader.join().unwrap();
    }
    // A writer paused mid-write: every attempt sees it and the read fails
    // closed, which counts as a torn snapshot.
    gate.hold_write_for_test();
    assert_eq!(gate.snapshot(), (Snapshot::FAIL_CLOSED, true));
    let counters = Counters::new();
    let relay_frame = tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN);
    assert_eq!(
        filter_packet(&gate, &counters, n("en0"), 2, &relay_frame),
        Verdict::Drop
    );
    assert_eq!(
        filter_packet(&gate, &counters, n("en0"), 2, &arp_frame()),
        Verdict::Allow
    );
    let values = counters.snapshot();
    assert_eq!(values[Reason::TornSnapshot.index().unwrap()], 2);
    assert_eq!(values[Reason::TcpOut.index().unwrap()], 1);
    assert_eq!(values[Reason::LinkControl.index().unwrap()], 1);
    gate.release_write_for_test();
    assert!(!gate.snapshot().1);
}

fn arp_frame() -> Vec<u8> {
    eth(ETHERTYPE_ARP, &[0, 1, 8, 0, 6, 4, 0, 1])
}

#[test]
fn filter_packet_counts_each_guarded_verdict_by_reason() {
    let gate = Gate::new();
    let counters = Counters::new();
    let token = gate.arm(Some(relay4()), false);
    let relay = tcp4(LOCAL, RELAY, 50000, RELAY_PORT, ACK);
    let leak = tcp4(LOCAL, PEER, 50000, 443, ACK);
    let echo = icmp6(local6(), gateway6(), 64, 129, b"ping");
    assert_eq!(
        filter_packet(&gate, &counters, n("en0"), 2, &relay),
        Verdict::Allow
    );
    for _ in 0..3 {
        assert_eq!(
            filter_packet(&gate, &counters, n("en0"), 2, &leak),
            Verdict::Drop
        );
    }
    assert_eq!(
        filter_packet(&gate, &counters, n("en0"), 2, &echo),
        Verdict::Drop
    );
    assert_eq!(
        filter_packet(&gate, &counters, n("utun4"), 2, &leak),
        Verdict::Allow
    );
    // No name, or an unknown direction: still guarded.
    assert_eq!(
        filter_packet(&gate, &counters, None, 9, &leak),
        Verdict::Drop
    );
    let values = counters.snapshot();
    let at = |reason: Reason| values[reason.index().unwrap()];
    assert_eq!(at(Reason::Relay), 1);
    assert_eq!(at(Reason::TcpOut), 4);
    assert_eq!(at(Reason::Icmp6Echo), 1);
    assert_eq!(at(Reason::TunnelIface), 1);
    assert_eq!(values.iter().sum::<u64>(), 7);
    let fields = counter_fields(&values);
    assert_eq!(
        fields,
        [
            "allow_tunnel_iface:1",
            "allow_relay:1",
            "drop_tcp_out:4",
            "drop_icmp6_echo:1"
        ]
    );
    // Disarmed: allowed again and nothing more counted.
    assert!(gate.disarm(token));
    assert_eq!(
        filter_packet(&gate, &counters, n("en0"), 2, &leak),
        Verdict::Allow
    );
    assert_eq!(counters.snapshot(), values);
}

#[test]
fn counter_slots_follow_the_reason_order_and_names_are_stable_tokens() {
    let mut names = std::collections::BTreeSet::new();
    for (slot, reason) in COUNTED.iter().enumerate() {
        assert_eq!(reason.index(), Some(slot), "{reason:?}");
        let name = reason.name();
        assert!(
            name.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "{name}"
        );
        assert!(name.len() <= 32, "{name}");
        assert!(names.insert(name), "{name}");
    }
    assert_eq!(Reason::Open.index(), None);
    assert!(!names.contains(Reason::Open.name()));
    let counters = Counters::new();
    counters.count(Reason::Open);
    assert_eq!(counters.snapshot(), [0; COUNTED.len()]);
    assert_eq!(std::mem::align_of::<Padded>(), 64);
    assert_eq!(counter_fields(&[0; COUNTED.len()]), Vec::<String>::new());
}

#[test]
fn endpoints_are_logged_by_family_only_and_mapped_addresses_compare_as_ipv4() {
    assert_eq!(family_token(Some(relay4())), "v4");
    assert_eq!(family_token(Some(peer(IpAddr::V6(relay6()), 443))), "v6");
    assert_eq!(family_token(None), "none");
    let mapped: SocketAddr = "[::ffff:203.0.113.10]:443".parse().unwrap();
    assert_eq!(Peer::from(mapped), relay4());
    let plain: SocketAddr = "203.0.113.10:9445".parse().unwrap();
    assert_eq!(Peer::from(plain), authority4());
    let six: SocketAddr = "[2001:db8:443::10]:443".parse().unwrap();
    assert_eq!(Peer::from(six), peer(IpAddr::V6(relay6()), 443));
}

#[test]
fn the_per_packet_path_never_allocates() {
    let gate = Gate::new();
    let counters = Counters::new();
    gate.arm(Some(relay4()), true);
    let mut frames = corpus();
    frames.push(chained(MAX_EXTENSION_HEADERS + 1, relay6()));
    frames.push(icmp6(
        peer6(),
        local6(),
        64,
        2,
        &quoted6(relay6(), PROTO_TCP, RELAY_PORT),
    ));
    let names = [n("en0"), n("utun2"), n("lo0"), None];
    let before = crate::test_alloc::allocations();
    let mut dropped = 0u32;
    for frame in &frames {
        for name in names {
            for direction in 0..3 {
                if filter_packet(&gate, &counters, name, direction, frame) == Verdict::Drop {
                    dropped += 1;
                }
            }
        }
    }
    let _ = gate.snapshot();
    let after = crate::test_alloc::allocations();
    assert_eq!(after, before, "the per-packet path allocated");
    assert!(dropped > 0);
    // The counter proves the allocator is counting on this thread.
    let boxed = std::hint::black_box(Box::new(dropped));
    assert!(crate::test_alloc::allocations() > after);
    std::mem::drop(boxed);
}

#[test]
fn icmp_types_next_to_the_allowed_ones_stay_dropped() {
    let s = armed();
    // Router renumbering and node information carry hop limit 255 too.
    for kind in [138, 139, 140, 141, 142] {
        assert_eq!(
            judge(
                &s,
                OUT,
                &icmp6(link_local(), gateway6(), 255, kind, &[0; 16])
            ),
            drop(Reason::Icmp6Other),
            "{kind}"
        );
    }
    // Hop limit 1 from a link-local source is MLD only for the MLD types.
    for kind in [129, 133, 139, 144, 151] {
        let expected = if kind == 129 {
            drop(Reason::Icmp6Echo)
        } else {
            drop(Reason::Icmp6Other)
        };
        assert_eq!(
            judge(&s, OUT, &icmp6(link_local(), gateway6(), 1, kind, &[0; 16])),
            expected,
            "{kind}"
        );
    }
}

#[test]
fn an_icmp_error_quoting_another_ip_version_is_not_a_relay_error() {
    let s6 = armed6();
    let mut wrong6 = quoted6(relay6(), PROTO_TCP, RELAY_PORT);
    wrong6[0] = 0x40;
    assert_eq!(
        judge(&s6, IN, &icmp6(peer6(), local6(), 64, 2, &wrong6)),
        drop(Reason::Icmp6Error)
    );
    let s = armed();
    let mut wrong4 = quoted4(RELAY, PROTO_TCP, RELAY_PORT);
    wrong4[0] = 0x65;
    let error = |quoted: &[u8]| {
        eth(
            ETHERTYPE_IPV4,
            &v4(PEER, LOCAL, PROTO_ICMP, &icmp(3, 4, quoted)),
        )
    };
    assert_eq!(judge(&s, IN, &error(&wrong4)), drop(Reason::Icmp4In));
    let mut short_ihl = quoted4(RELAY, PROTO_TCP, RELAY_PORT);
    short_ihl[0] = 0x44;
    assert_eq!(judge(&s, IN, &error(&short_ihl)), drop(Reason::Icmp4In));
    assert_eq!(
        judge(&s, IN, &error(&quoted4(RELAY, PROTO_TCP, RELAY_PORT))),
        allow(Reason::RelayIcmpError)
    );
}

#[test]
fn a_first_fragment_with_more_fragments_is_judged_by_its_upper_layer() {
    let s6 = armed6();
    for (dst, expected) in [
        (relay6(), allow(Reason::Relay)),
        (peer6(), drop(Reason::TcpOut)),
    ] {
        let mut rest = frag6(PROTO_TCP, 0, true);
        rest.extend_from_slice(&tcp(50000, RELAY_PORT, ACK, &[3; 16]));
        assert_eq!(
            judge(
                &s6,
                OUT,
                &eth(ETHERTYPE_IPV6, &v6(local6(), dst, 44, 64, &rest))
            ),
            expected
        );
    }
}

#[test]
fn headers_cut_short_by_the_ip_length_never_read_the_ethernet_padding() {
    let s = armed();
    // IPv4: the TCP header ends after its source port; the padding would
    // spell the relay port.
    let mut frame = eth(ETHERTYPE_IPV4, &v4(LOCAL, RELAY, PROTO_TCP, &[0xc3, 0x50]));
    frame.extend_from_slice(&[0x01, 0xbb, 0, 0, 0, 0, 0, 0]);
    assert_eq!(judge(&s, OUT, &frame), drop(Reason::Malformed));
    // IPv6: the same, and a Fragment header cut short by the payload length.
    let s6 = armed6();
    let mut frame6 = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), relay6(), PROTO_TCP, 64, &[0xc3, 0x50]),
    );
    frame6.extend_from_slice(&[0x01, 0xbb, 0, 0, 0, 0, 0, 0]);
    assert_eq!(judge(&s6, OUT, &frame6), drop(Reason::Malformed));
    let mut fragment = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), relay6(), 44, 64, &[PROTO_TCP, 0, 0]),
    );
    fragment.extend_from_slice(&[0; 32]);
    assert_eq!(judge(&s6, OUT, &fragment), drop(Reason::Malformed));
    let mut options = eth(
        ETHERTYPE_IPV6,
        &v6(local6(), relay6(), 60, 64, &[PROTO_TCP, 0, 0]),
    );
    options.extend_from_slice(&[0; 32]);
    assert_eq!(judge(&s6, OUT, &options), drop(Reason::Malformed));
}

#[test]
fn the_ip_parsers_refuse_inconsistent_headers_on_their_own() {
    let good = v4(LOCAL, RELAY, PROTO_TCP, &tcp(50000, RELAY_PORT, ACK, &[]));
    assert!(ip_consistent(&good, true) && ip_consistent(&good, false));
    assert!(parse_ip(&good).is_some());
    let mut ihl = good.clone();
    ihl[0] = 0x44;
    let mut total_short = good.clone();
    total_short[2..4].copy_from_slice(&16u16.to_be_bytes());
    let mut total_long = good.clone();
    total_long[2..4].copy_from_slice(&((good.len() + 1) as u16).to_be_bytes());
    for bad in [&ihl, &total_short, &total_long] {
        assert!(!ip_consistent(bad, false));
        assert!(!ip_consistent(bad, true));
        assert!(parse_ip(bad).is_none());
    }
    let good6 = v6(
        local6(),
        relay6(),
        PROTO_TCP,
        64,
        &tcp(50000, RELAY_PORT, ACK, &[]),
    );
    assert!(ip_consistent(&good6, true));
    assert!(parse_ip(&good6).is_some());
    let mut long6 = good6.clone();
    long6[4..6].copy_from_slice(&((good6.len() - 39) as u16).to_be_bytes());
    assert!(!ip_consistent(&long6, false));
    assert!(parse_ip(&long6).is_none());
    // Padding: consistent within a frame, never as an exact raw packet.
    let mut padded = good.clone();
    padded.push(0);
    assert!(ip_consistent(&padded, false));
    assert!(!ip_consistent(&padded, true));
    assert!(!ip_consistent(&[], false));
    assert!(!ip_consistent(&[0x60, 0, 0, 0, 0], false));
}

#[test]
fn direction_any_prefers_the_outbound_reading_when_both_allow() {
    // Relay host to itself on the relay port both ways (v31: S20b used the
    // authority port inbound, which no longer passes). Contrived, but it
    // fixes which reason is counted.
    let s = armed();
    let frame = tcp4(RELAY, RELAY, RELAY_PORT, RELAY_PORT, ACK);
    assert_eq!(judge(&s, ANY, &frame), allow(Reason::Relay));
    assert_eq!(judge(&s, IN, &frame), allow(Reason::Relay));
    // The S20b frame: only its outbound reading passes now.
    let frame = tcp4(RELAY, RELAY, AUTHORITY_PORT, RELAY_PORT, ACK);
    assert_eq!(judge(&s, ANY, &frame), allow(Reason::Relay));
    assert_eq!(judge(&s, IN, &frame), drop(Reason::TcpIn));
}

/// xorshift64*: deterministic bytes for the robustness test.
fn next(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

#[test]
fn arbitrary_and_truncated_frames_never_panic_and_never_allow_a_non_relay_flow() {
    let s = guarding(Some(relay4()), true);
    let mut state = 0x5eed_u64;
    for _ in 0..20_000 {
        let length = (next(&mut state) % 160) as usize;
        let mut frame: Vec<u8> = (0..length).map(|_| next(&mut state) as u8).collect();
        // Half of them get a plausible ethertype and IP version.
        if length > 15 && next(&mut state).is_multiple_of(2) {
            let six = next(&mut state).is_multiple_of(2);
            frame[12..14]
                .copy_from_slice(&if six { ETHERTYPE_IPV6 } else { ETHERTYPE_IPV4 }.to_be_bytes());
            frame[14] = if six { 0x60 } else { 0x45 };
        }
        for direction in [OUT, IN, ANY] {
            let _ = judge(&s, direction, &frame);
        }
    }
    // Every prefix of every corpus frame, and every single-byte change of a
    // non-relay TCP frame: never a panic, and the leak is never allowed as
    // relay traffic unless the change made it one (v31: never as the
    // retired authority reason at all).
    let leak = tcp4(LOCAL, PEER, 50000, 443, ACK);
    for frame in corpus()
        .into_iter()
        .chain([leak.clone(), chained(3, relay6())])
    {
        for end in 0..=frame.len() {
            for direction in [OUT, IN, ANY] {
                let _ = judge(&s, direction, &frame[..end]);
            }
        }
    }
    for at in 0..leak.len() {
        for value in [0u8, 0x01, 0x45, 0xbb, 0xff] {
            let mut changed = leak.clone();
            changed[at] = value;
            let (verdict, reason) = judge(&s, OUT, &changed);
            if verdict == Verdict::Allow {
                assert!(
                    matches!(
                        reason,
                        Reason::LinkControl | Reason::Dhcp4 | Reason::Relay | Reason::RelayFragment
                    ),
                    "byte {at} = {value:#x}: {reason:?}"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// v40 (CP-D3 M1): the armed pin set of a carrier pool.

const EDGE_A: [u8; 4] = [198, 51, 100, 20];
const EDGE_B: [u8; 4] = [198, 51, 100, 21];

/// The production pool shape: a direct relay and two CDN edge pins, all on
/// 443, as a fronted v4 profile pins them.
fn pool_pins() -> PeerSet {
    PeerSet::new(&[
        relay4(),
        v4_peer(EDGE_A, RELAY_PORT).unwrap(),
        v4_peer(EDGE_B, RELAY_PORT).unwrap(),
    ])
    .unwrap()
}

fn pool_armed(udp_relay: bool) -> Snapshot {
    Snapshot {
        mode: Mode::Guarding,
        token: 9,
        relays: pool_pins(),
        udp_relay,
        udp_media: PeerSet::EMPTY,
    }
}

#[test]
fn sfu_udp_candidate_is_exact_separate_and_withdrawn_without_opening_h2_udp() {
    let gate = Gate::new();
    let token = gate.arm_pins(&pool_pins(), false);
    let sfu: SocketAddr = "198.51.100.22:7882".parse().unwrap();
    assert!(gate.amend_udp_media(token, sfu));
    assert!(gate.amend_udp_media(token, sfu));
    let (snapshot, torn) = gate.snapshot();
    assert!(!torn);
    assert!(!snapshot.udp_relay);
    assert_eq!(snapshot.udp_media, PeerSet::one(Some(sfu.into())));
    assert_eq!(
        judge(
            &snapshot,
            OUT,
            &udp4(LOCAL, [198, 51, 100, 22], 50000, 7882)
        ),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&snapshot, IN, &udp4([198, 51, 100, 22], LOCAL, 7882, 50000)),
        allow(Reason::Relay)
    );
    assert_eq!(
        judge(&snapshot, OUT, &udp4(LOCAL, RELAY, 50000, RELAY_PORT)),
        drop(Reason::Udp)
    );
    assert_eq!(
        judge(
            &snapshot,
            OUT,
            &udp4(LOCAL, [198, 51, 100, 22], 50000, 7883)
        ),
        drop(Reason::Udp)
    );
    assert!(!gate.amend_udp_media(token, "0.0.0.0:7882".parse().unwrap()));
    assert!(gate.withdraw_udp_media(token, sfu));
    assert!(gate.snapshot().0.udp_media.is_empty());
    assert!(!gate.withdraw_udp_media(token, sfu));
    let next = gate.arm_pins(&pool_pins(), false);
    assert!(!gate.amend_udp_media(token, sfu));
    assert!(gate.snapshot().0.udp_media.is_empty());
    assert!(gate.disarm(next));
}

#[test]
fn a_pool_arm_allows_every_exact_pin_both_ways_and_nothing_else() {
    let s = pool_armed(false);
    for pin in [RELAY, EDGE_A, EDGE_B] {
        assert_eq!(
            judge(&s, OUT, &tcp4(LOCAL, pin, 50000, RELAY_PORT, SYN)),
            allow(Reason::Relay),
            "{pin:?}"
        );
        assert_eq!(
            judge(&s, IN, &tcp4(pin, LOCAL, RELAY_PORT, 50000, ACK)),
            allow(Reason::Relay)
        );
        assert_eq!(
            judge(&s, ANY, &tcp4(pin, LOCAL, RELAY_PORT, 50000, PSH_ACK)),
            allow(Reason::Relay)
        );
        // Each pin's address on another port is no pin.
        for port in [80, 444, 8443, AUTHORITY_PORT] {
            assert_eq!(
                judge(&s, OUT, &tcp4(LOCAL, pin, 50000, port, SYN)),
                drop(Reason::TcpOut),
                "{pin:?}:{port}"
            );
            assert_eq!(
                judge(&s, IN, &tcp4(pin, LOCAL, port, 50000, ACK)),
                drop(Reason::TcpIn)
            );
        }
        // UDP to a pin is relay traffic only when the carrier allows UDP.
        assert_eq!(
            judge(&s, OUT, &udp4(LOCAL, pin, 50000, RELAY_PORT)),
            drop(Reason::Udp)
        );
        assert_eq!(
            judge(&pool_armed(true), OUT, &udp4(LOCAL, pin, 50000, RELAY_PORT)),
            allow(Reason::Relay)
        );
    }
    // Neighbours of the pins, and any other host on 443, are not pins.
    for other in [
        [198, 51, 100, 22],
        [198, 51, 100, 19],
        [203, 0, 113, 11],
        PEER,
        GATEWAY,
    ] {
        assert_eq!(
            judge(&s, OUT, &tcp4(LOCAL, other, 50000, RELAY_PORT, SYN)),
            drop(Reason::TcpOut),
            "{other:?}"
        );
        assert_eq!(
            judge(
                &pool_armed(true),
                OUT,
                &udp4(LOCAL, other, 50000, RELAY_PORT)
            ),
            drop(Reason::Udp)
        );
    }
}

#[test]
fn a_pool_arm_allows_icmp_errors_and_later_fragments_only_for_its_pins() {
    let s = pool_armed(false);
    let later = |src, dst| {
        eth(
            ETHERTYPE_IPV4,
            &v4_full(src, dst, PROTO_TCP, 64, 185, &[0xaa; 24]),
        )
    };
    for pin in [RELAY, EDGE_A, EDGE_B] {
        assert_eq!(
            judge(&s, OUT, &later(LOCAL, pin)),
            allow(Reason::RelayFragment)
        );
        // Fragmentation needed quoting our segment to the pin.
        let error = eth(
            ETHERTYPE_IPV4,
            &v4(
                GATEWAY,
                LOCAL,
                PROTO_ICMP,
                &icmp(3, 4, &quoted4(pin, PROTO_TCP, RELAY_PORT)),
            ),
        );
        assert_eq!(judge(&s, IN, &error), allow(Reason::RelayIcmpError));
        // The same error quoting another port of the pin's host drops.
        let other_port = eth(
            ETHERTYPE_IPV4,
            &v4(
                GATEWAY,
                LOCAL,
                PROTO_ICMP,
                &icmp(3, 4, &quoted4(pin, PROTO_TCP, 80)),
            ),
        );
        assert_eq!(judge(&s, IN, &other_port), drop(Reason::Icmp4In));
    }
    assert_eq!(judge(&s, OUT, &later(LOCAL, PEER)), drop(Reason::Fragment));
}

#[test]
fn a_pin_set_is_exact_bounded_and_never_truncated() {
    let pins = pool_pins();
    assert_eq!(pins.len(), 3);
    assert_eq!(pins.first(), Some(relay4()));
    // A repeated pin is kept once; an IPv4-mapped pin is its IPv4 pin.
    let mapped = peer(
        IpAddr::V6(Ipv4Addr::from(EDGE_A).to_ipv6_mapped()),
        RELAY_PORT,
    );
    let with_repeats = PeerSet::new(&[
        relay4(),
        relay4(),
        mapped,
        v4_peer(EDGE_A, RELAY_PORT).unwrap(),
        v4_peer(EDGE_B, RELAY_PORT).unwrap(),
    ])
    .unwrap();
    assert_eq!(with_repeats, pins);
    // At most MAX_RELAY_PINS distinct pins; one more is refused whole.
    let many: Vec<Peer> = (0..MAX_RELAY_PINS as u8)
        .map(|n| v4_peer([198, 51, 100, n], RELAY_PORT).unwrap())
        .collect();
    let full = PeerSet::new(&many).unwrap();
    assert_eq!(full.len(), MAX_RELAY_PINS);
    let mut too_many = many.clone();
    too_many.push(v4_peer([198, 51, 100, 200], RELAY_PORT).unwrap());
    assert_eq!(PeerSet::new(&too_many), None);
    assert!(PeerSet::new(&[]).unwrap().is_empty());
    assert_eq!(PeerSet::one(None), PeerSet::EMPTY);
    assert_eq!(
        pins_family_token(&pins),
        "v4",
        "an address-free family token"
    );
    let mixed = PeerSet::new(&[relay4(), peer(IpAddr::V6(relay6()), RELAY_PORT)]).unwrap();
    assert_eq!(pins_family_token(&mixed), "mixed");
    assert_eq!(pins_family_token(&PeerSet::EMPTY), "none");
}

#[test]
fn the_gate_arms_and_reads_back_the_whole_pool_and_refuses_dials_off_it() {
    let gate = Gate::new();
    let token = gate.arm_pins(&pool_pins(), false);
    let (s, torn) = gate.snapshot();
    assert!(!torn);
    assert_eq!(s, pool_armed(false).with_token(token.get()));
    for pin in ["203.0.113.10:443", "198.51.100.20:443", "198.51.100.21:443"] {
        assert!(!gate.dial_refused(pin.parse().unwrap()), "{pin}");
    }
    for other in [
        "203.0.113.10:9445",
        "198.51.100.20:8443",
        "198.51.100.22:443",
        "192.0.2.1:443",
    ] {
        assert!(gate.dial_refused(other.parse().unwrap()), "{other}");
    }
    // A re-arm with one pin drops the others: nothing stale stays allowed.
    let single = gate.arm(Some(relay4()), false);
    let (s, _) = gate.snapshot();
    assert_eq!(s.relays, PeerSet::one(Some(relay4())));
    assert!(gate.dial_refused("198.51.100.20:443".parse().unwrap()));
    assert_eq!(
        judge(&s, OUT, &tcp4(LOCAL, EDGE_A, 50000, RELAY_PORT, SYN)),
        drop(Reason::TcpOut)
    );
    // An empty set guards with nothing but link control (fail closed).
    let empty = gate.arm_pins(&PeerSet::EMPTY, false);
    assert!(gate.dial_refused("203.0.113.10:443".parse().unwrap()));
    assert!(
        !gate.disarm(single),
        "a superseded arm never opens the gate"
    );
    assert!(gate.disarm(empty));
    assert!(!gate.dial_refused("192.0.2.1:443".parse().unwrap()), "open");
}

#[test]
fn authenticated_descriptor_amendment_is_exact_tcp_only_and_token_bound() {
    let gate = Gate::new();
    let base = gate.arm_pins(&pool_pins(), false);
    let ingress: SocketAddr = "198.51.100.22:9443".parse().unwrap();
    assert!(gate.dial_refused(ingress));
    assert!(!gate.amend_tcp_pin(base, "0.0.0.0:9443".parse().unwrap()));
    assert!(!gate.amend_tcp_pin(base, "198.51.100.22:0".parse().unwrap()));
    assert!(gate.amend_tcp_pin(base, ingress));
    assert!(gate.amend_tcp_pin(base, ingress));
    let (snapshot, torn) = gate.snapshot();
    assert!(!torn);
    assert_eq!(snapshot.token, base.get());
    assert!(!gate.dial_refused(ingress));
    assert!(gate.dial_refused("198.51.100.22:9444".parse().unwrap()));
    assert_eq!(
        judge(
            &snapshot,
            OUT,
            &udp4(LOCAL, [198, 51, 100, 22], 50000, 9443)
        ),
        drop(Reason::Udp)
    );
    assert!(!gate.withdraw_tcp_pin(base, "203.0.113.10:443".parse().unwrap()));
    assert!(gate.withdraw_tcp_pin(base, ingress));
    assert!(gate.dial_refused(ingress));
    assert!(!gate.withdraw_tcp_pin(base, ingress));
    let next = gate.arm_pins(&pool_pins(), false);
    assert!(!gate.amend_tcp_pin(base, ingress));
    assert!(gate.dial_refused(ingress));
    assert!(gate.disarm(next));
    assert!(!gate.amend_tcp_pin(next, ingress));

    let mut full = Vec::new();
    for i in 1..=MAX_RELAY_PINS {
        full.push(peer(IpAddr::V4(Ipv4Addr::new(198, 51, 100, i as u8)), 443));
    }
    let full = PeerSet::new(&full).unwrap();
    let full_token = gate.arm_pins(&full, false);
    assert!(!gate.amend_tcp_pin(full_token, ingress));
    let udp_token = gate.arm_pins(&pool_pins(), true);
    assert!(!gate.amend_tcp_pin(udp_token, ingress));
}

#[test]
fn a_reader_never_sees_a_mixed_pool_while_pools_are_rearmed() {
    let gate = Arc::new(Gate::new());
    let a = pool_pins();
    let b = PeerSet::new(&[
        peer(IpAddr::V6("2001:db8:bbbb::1".parse().unwrap()), 2222),
        peer(IpAddr::V6("2001:db8:bbbb::2".parse().unwrap()), 2223),
    ])
    .unwrap();
    gate.arm_pins(&a, false);
    let writers: Vec<_> = (0..2)
        .map(|w| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                for i in 0..10_000u64 {
                    if (i + w) % 2 == 0 {
                        gate.arm_pins(&a, false);
                    } else {
                        gate.arm_pins(&b, true);
                    }
                }
            })
        })
        .collect();
    let readers: Vec<_> = (0..2)
        .map(|_| {
            let gate = gate.clone();
            std::thread::spawn(move || {
                for _ in 0..20_000 {
                    let (s, torn) = gate.snapshot();
                    if torn {
                        assert_eq!(s, Snapshot::FAIL_CLOSED);
                        continue;
                    }
                    assert!(
                        (s.relays == a && !s.udp_relay) || (s.relays == b && s.udp_relay),
                        "mixed snapshot {s:?}"
                    );
                }
            })
        })
        .collect();
    for thread in writers.into_iter().chain(readers) {
        thread.join().unwrap();
    }
}

#[test]
fn the_per_packet_path_never_allocates_with_a_pool_armed() {
    let gate = Gate::new();
    let counters = Counters::new();
    gate.arm_pins(&pool_pins(), true);
    let frames = corpus();
    let names = [n("en0"), n("utun2"), None];
    let before = crate::test_alloc::allocations();
    let mut allowed = 0u32;
    for frame in &frames {
        for name in names {
            for direction in 0..3 {
                if filter_packet(&gate, &counters, name, direction, frame) == Verdict::Allow {
                    allowed += 1;
                }
            }
        }
    }
    assert_eq!(crate::test_alloc::allocations(), before);
    assert!(allowed > 0);
}
