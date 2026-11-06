//! v27 (S20f) observability of the leak guard over synthetic frames: drops
//! by interface class and direction, the drop ring, the arm accounting.
//! Documentation addresses only; nothing is sent or captured.
use super::*;
use std::sync::Arc;

const LOCAL: [u8; 4] = [192, 0, 2, 50];
const PEER: [u8; 4] = [198, 51, 100, 9];
const RELAY: [u8; 4] = [203, 0, 113, 10];
const RELAY_PORT: u16 = 443;
const OUT: isize = 2;
const IN: isize = 1;
const ANY: isize = 0;
const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;

fn n(name: &str) -> Option<&[u8]> {
    Some(name.as_bytes())
}

fn relay() -> Peer {
    Peer {
        ip: IpAddr::V4(Ipv4Addr::from(RELAY)),
        port: RELAY_PORT,
    }
}

fn tcp(sport: u16, dport: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut l4 = Vec::new();
    l4.extend_from_slice(&sport.to_be_bytes());
    l4.extend_from_slice(&dport.to_be_bytes());
    l4.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    l4.extend_from_slice(payload);
    l4
}

fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, fragment: u16, l4: &[u8]) -> Vec<u8> {
    let total = (20 + l4.len()) as u16;
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&fragment.to_be_bytes());
    packet.extend_from_slice(&[64, proto, 0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(l4);
    packet
}

fn v6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, l4: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    packet.extend_from_slice(&[next, 64]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(l4);
    packet
}

fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x02, 0, 0, 0, 0, 0x01, 0x02, 0, 0, 0, 0, 0x02];
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

fn tcp4(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
    eth(
        ETHERTYPE_IPV4,
        &v4(src, dst, PROTO_TCP, 0x4000, &tcp(sport, dport, flags, b"")),
    )
}

fn leak_out() -> Vec<u8> {
    tcp4(LOCAL, PEER, 50000, 443, SYN)
}

fn leak_in() -> Vec<u8> {
    tcp4(PEER, LOCAL, 443, 50000, ACK)
}

fn armed_gate() -> Gate {
    let gate = Gate::new();
    gate.arm(Some(relay()), false);
    gate
}

fn total_drops(counters: &Counters) -> u64 {
    COUNTED
        .iter()
        .zip(counters.snapshot())
        .filter(|(reason, _)| reason.name().starts_with("drop_"))
        .map(|(_, value)| value)
        .sum()
}

fn record(arm_seq: u32, ms: u32, name: &str) -> DropRecord {
    DropRecord {
        arm_seq,
        ms,
        iface: iface_code(n(name)),
        class: DropClass::EnOther,
        direction: Direction::Outbound,
        family: 4,
        protocol: PROTO_TCP,
        tcp: TcpClass::Syn,
        reason: Reason::TcpOut,
    }
}

#[test]
fn drops_are_counted_by_interface_class_and_direction() {
    let gate = armed_gate();
    gate.set_primary(n("en7"));
    let counters = Counters::new();
    let cases: [(Option<&[u8]>, isize, DropClass, Direction); 12] = [
        (n("en7"), OUT, DropClass::Primary, Direction::Outbound),
        (n("en7"), IN, DropClass::Primary, Direction::Inbound),
        (n("en0"), OUT, DropClass::EnOther, Direction::Outbound),
        (n("en10"), ANY, DropClass::EnOther, Direction::Any),
        (n("awdl0"), OUT, DropClass::AwdlLlw, Direction::Outbound),
        (n("llw0"), IN, DropClass::AwdlLlw, Direction::Inbound),
        (
            n("bridge100"),
            OUT,
            DropClass::BridgeApAnpi,
            Direction::Outbound,
        ),
        (n("ap1"), OUT, DropClass::BridgeApAnpi, Direction::Outbound),
        (n("anpi0"), 9, DropClass::BridgeApAnpi, Direction::Any),
        (None, OUT, DropClass::Other, Direction::Outbound),
        (n("vmenet0"), IN, DropClass::Other, Direction::Inbound),
        (
            n("Wi-Fi of a user"),
            OUT,
            DropClass::Other,
            Direction::Outbound,
        ),
    ];
    let mut expected = [[0u64; 3]; 5];
    for (name, direction, class, slot) in cases {
        let frame = if direction == IN {
            leak_in()
        } else {
            leak_out()
        };
        assert_eq!(
            filter_packet(&gate, &counters, name, direction, &frame),
            Verdict::Drop
        );
        expected[class.slot()][slot.slot()] += 1;
    }
    // Allowed packets are never counted as drops: the relay on the pinned
    // interface, a tunnel interface, link control.
    let relay_syn = tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN);
    assert_eq!(
        filter_packet(&gate, &counters, n("en7"), OUT, &relay_syn),
        Verdict::Allow
    );
    assert_eq!(
        filter_packet(&gate, &counters, n("utun3"), OUT, &leak_out()),
        Verdict::Allow
    );
    assert_eq!(
        filter_packet(
            &gate,
            &counters,
            n("en7"),
            OUT,
            &eth(ETHERTYPE_ARP, &[0, 1, 8, 0, 6, 4, 0, 1])
        ),
        Verdict::Allow
    );
    assert_eq!(counters.drop_snapshot(), expected);
    let by_class: u64 = counters.drop_snapshot().iter().flatten().sum();
    assert_eq!(by_class, total_drops(&counters));
    assert_eq!(counters.ring().snapshot().next, by_class);
    // Open: nothing is counted at all.
    let before = counters.drop_snapshot();
    let open = Gate::new();
    assert_eq!(
        filter_packet(&open, &counters, n("en7"), OUT, &leak_out()),
        Verdict::Allow
    );
    assert_eq!(counters.drop_snapshot(), before);
    assert_eq!(counters.ring().snapshot().next, by_class);
    for (class, name) in
        DROP_CLASSES
            .iter()
            .zip(["primary", "en_other", "awdl_llw", "bridge_ap_anpi", "other"])
    {
        assert_eq!(class.name(), name);
    }
    assert_eq!(
        DIRECTIONS.map(Direction::name),
        ["in", "out", "any"],
        "slot order"
    );
}

#[test]
fn the_primary_class_follows_the_pinned_interface() {
    let gate = armed_gate();
    let counters = Counters::new();
    let drop_on = |name| {
        filter_packet(&gate, &counters, n(name), OUT, &leak_out());
        counters.ring().snapshot().entries.last().unwrap().1.class
    };
    assert_eq!(gate.primary(), 0);
    assert_eq!(drop_on("en7"), DropClass::EnOther, "nothing pinned");
    gate.set_primary(n("en7"));
    assert_eq!(gate.primary(), iface_code(n("en7")));
    assert_eq!(drop_on("en7"), DropClass::Primary);
    assert_eq!(drop_on("en0"), DropClass::EnOther);
    // A re-pin moves it; a pin that is no known name still compares.
    gate.set_primary(n("en0"));
    assert_eq!(drop_on("en0"), DropClass::Primary);
    assert_eq!(drop_on("en7"), DropClass::EnOther);
    gate.set_primary(n("eth-weird"));
    assert_eq!(drop_on("eth-weird"), DropClass::Primary);
    gate.set_primary(None);
    assert_eq!(drop_on("en0"), DropClass::EnOther);
    // A missing name is never primary, even with nothing pinned.
    assert_eq!(drop_class(0, 0), DropClass::Other);
}

#[test]
fn iface_codes_keep_known_names_and_hash_every_other_one() {
    for name in [
        "en0",
        "en7",
        "en9999",
        "awdl0",
        "llw0",
        "bridge100",
        "ap1",
        "anpi2",
        "utun12",
        "ipsec0",
        "lo0",
        "gif0",
        "stf0",
        "pktap0",
        "vmenet3",
        "vmnet8",
        "vnic0",
    ] {
        let code = iface_code(n(name));
        assert_ne!(code & IFACE_NAMED, 0, "{name}");
        assert_eq!(iface_token(code), name);
        assert!(iface_token_valid(name), "{name}");
    }
    let long = "x".repeat(100);
    for name in [
        "en01",
        "en",
        "EN0",
        "en10000",
        "my wifi",
        "home-network",
        long.as_str(),
        "192.0.2.1",
    ] {
        let code = iface_code(n(name));
        assert_eq!(code & IFACE_NAMED, 0, "{name}");
        assert_ne!(code, 0, "{name}");
        let token = iface_token(code);
        assert!(token.starts_with("h:") && token.len() == 10, "{token}");
        assert!(!token.contains(name), "{token}");
        assert!(iface_token_valid(&token), "{token}");
    }
    // A hash reads at most 32 bytes and the length (bounded per packet):
    // equal prefixes of different lengths still differ, names that differ
    // only past byte 32 share a code, and it is deterministic.
    let a = "y".repeat(40);
    let b = "y".repeat(41);
    assert_ne!(iface_code(n(&a)), iface_code(n(&b)));
    assert_eq!(iface_code(n(&a)), iface_code(n(&a)));
    let late = format!("{}{}", "y".repeat(32), "z".repeat(8));
    assert_eq!(iface_code(n(&late)), iface_code(n(&a)));
    assert_eq!(iface_code(None), 0);
    assert_eq!(iface_token(0), "none");
    assert!(iface_token_valid("none"));
    for bad in [
        "",
        "en",
        "en00",
        "en01",
        "en10000",
        "h:0",
        "h:00000000",
        "h:80000000",
        "h:ABCDEF12",
        "h:abcdef1",
        "h:abcdef123",
        "192.0.2.1",
        "fe80::1",
        "wlan0",
        "en 0",
        "en0 ",
    ] {
        assert!(!iface_token_valid(bad), "{bad:?}");
    }
}

#[test]
fn the_ring_keeps_the_last_64_drops_in_order_and_wraps() {
    let ring = DropRing::new();
    assert_eq!(
        ring.snapshot(),
        RingSnapshot {
            next: 0,
            skipped: 0,
            torn: 0,
            entries: vec![]
        }
    );
    for i in 0..150u32 {
        ring.record(&record(1, i, "en0"));
    }
    let snapshot = ring.snapshot();
    assert_eq!(
        (snapshot.next, snapshot.skipped, snapshot.torn),
        (150, 0, 0)
    );
    assert_eq!(snapshot.entries.len(), RING_SLOTS);
    for (k, (index, entry)) in snapshot.entries.iter().enumerate() {
        assert_eq!(*index, 86 + k as u64);
        assert_eq!(entry.ms, 86 + k as u32);
        assert_eq!(*entry, record(1, entry.ms, "en0"));
    }
    // Fewer than a ring's worth: every one, oldest first.
    let short = DropRing::new();
    for i in 0..5u32 {
        short.record(&record(2, i * 10, "awdl0"));
    }
    let entries = short.snapshot().entries;
    assert_eq!(
        entries.iter().map(|(i, e)| (*i, e.ms)).collect::<Vec<_>>(),
        [(0, 0), (1, 10), (2, 20), (3, 30), (4, 40)]
    );
}

#[test]
fn a_torn_or_undecodable_ring_slot_is_detected_and_never_reported() {
    let ring = DropRing::new();
    for i in 0..10u32 {
        ring.record(&record(1, i, "en0"));
    }
    ring.hold_slot_for_test(3);
    let snapshot = ring.snapshot();
    assert_eq!(snapshot.torn, 1);
    assert_eq!(snapshot.entries.len(), 9);
    assert!(snapshot.entries.iter().all(|(index, _)| *index != 3));
    ring.release_slot_for_test(3);
    let snapshot = ring.snapshot();
    assert_eq!((snapshot.torn, snapshot.entries.len()), (0, 10));
    // Words that do not decode are counted as torn too.
    ring.corrupt_slot_for_test(5);
    let snapshot = ring.snapshot();
    assert_eq!((snapshot.torn, snapshot.entries.len()), (1, 9));
    assert!(snapshot.entries.iter().all(|(index, _)| *index != 5));
}

#[test]
fn a_writer_meeting_a_busy_or_newer_slot_skips_without_waiting() {
    let ring = DropRing::new();
    // Slot 0 held by a writer paused mid-write: the next record into it skips.
    ring.hold_slot_for_test(0);
    ring.record(&record(1, 0, "en0"));
    let snapshot = ring.snapshot();
    assert_eq!((snapshot.next, snapshot.skipped), (1, 1));
    assert_eq!(snapshot.torn, 1, "the held slot reads torn");
    ring.release_slot_for_test(0);
    // A writer of index 3 delayed past the writer of index 67 (same slot)
    // never overwrites the newer record.
    let ring = DropRing::new();
    for i in 0..68u32 {
        ring.record(&record(1, i, "en0"));
    }
    ring.write_stale_for_test(3, &record(9, 9999, "en7"));
    let snapshot = ring.snapshot();
    assert_eq!(snapshot.skipped, 1);
    let at3 = snapshot
        .entries
        .iter()
        .find(|(index, _)| *index == 67)
        .unwrap();
    assert_eq!(at3.1, record(1, 67, "en0"));
    assert!(snapshot.entries.iter().all(|(_, e)| e.arm_seq == 1));
}

#[test]
fn concurrent_ring_writers_never_produce_a_mixed_record() {
    // Each writer's records carry its own number in every field, so a
    // record mixing two writers' words cannot pass the check.
    let counters = Arc::new(Counters::new());
    let expected = |t: u32, ms: u32| DropRecord {
        arm_seq: t,
        ms,
        iface: iface_code(n(&format!("en{t}"))),
        class: DROP_CLASSES[t as usize % DROP_CLASSES.len()],
        direction: DIRECTIONS[t as usize % DIRECTIONS.len()],
        family: if t.is_multiple_of(2) { 4 } else { 6 },
        protocol: t as u8,
        tcp: TCP_CLASSES[t as usize % TCP_CLASSES.len()],
        reason: COUNTED[t as usize],
    };
    const WRITERS: u32 = 4;
    const EACH: u32 = 20_000;
    let stop = Arc::new(AtomicBool::new(false));
    let reader = {
        let counters = counters.clone();
        let stop = stop.clone();
        std::thread::spawn(move || {
            let mut checked = 0u64;
            loop {
                let done = stop.load(Ordering::Relaxed);
                let snapshot = counters.ring().snapshot();
                let mut last = None;
                for (index, entry) in &snapshot.entries {
                    assert!(last < Some(*index), "indices increase");
                    last = Some(*index);
                    assert_eq!(*entry, expected(entry.arm_seq, entry.ms), "mixed record");
                    checked += 1;
                }
                if done {
                    break;
                }
            }
            checked
        })
    };
    let writers: Vec<_> = (0..WRITERS)
        .map(|t| {
            let counters = counters.clone();
            std::thread::spawn(move || {
                for k in 0..EACH {
                    counters.ring().record(&expected(t, k));
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    let checked = reader.join().unwrap();
    let snapshot = counters.ring().snapshot();
    assert_eq!(snapshot.next, u64::from(WRITERS * EACH));
    assert_eq!(snapshot.torn, 0, "quiescent: nothing torn");
    assert!(snapshot.entries.len() <= RING_SLOTS);
    assert!(snapshot.entries.len() as u64 >= RING_SLOTS as u64 - snapshot.skipped.min(64));
    for (_, entry) in &snapshot.entries {
        assert_eq!(*entry, expected(entry.arm_seq, entry.ms));
    }
    assert!(checked > 0, "the reader saw records");
}

#[test]
fn packed_records_round_trip_and_out_of_range_fields_never_decode() {
    for class in DROP_CLASSES {
        for direction in DIRECTIONS {
            for tcp in TCP_CLASSES {
                for (family, reason) in [
                    (0, Reason::NonIp),
                    (4, Reason::TcpOut),
                    (6, Reason::OtherProto),
                ] {
                    let record = DropRecord {
                        arm_seq: u32::MAX,
                        ms: u32::MAX - 1,
                        iface: iface_code(n("bridge100")),
                        class,
                        direction,
                        family,
                        protocol: 255,
                        tcp,
                        reason,
                    };
                    let (a, b) = record.pack();
                    assert_eq!(DropRecord::unpack(a, b), Some(record));
                }
            }
        }
    }
    let (a, b) = record(1, 2, "en0").pack();
    assert_eq!(DropRecord::unpack(a, 0), None, "an empty slot");
    assert_eq!(DropRecord::unpack(a, b & !RECORD_VALID), None);
    for (shift, value) in [(0, 7u64), (3, 3), (5, 3), (10, 31)] {
        let bits = if shift == 10 {
            0x1f
        } else if shift == 0 {
            0x7
        } else {
            0x3
        };
        let changed = (b & !(bits << shift)) | (value << shift);
        assert_eq!(DropRecord::unpack(a, changed), None, "shift {shift}");
    }
}

/// A frame, its raw direction and interface name, and the family, protocol,
/// TCP class and reason its ring record must carry.
type DropCase = (Vec<u8>, isize, &'static str, u8, u8, TcpClass, Reason);

#[test]
fn ring_records_carry_ms_since_the_arm_and_only_header_classes() {
    let gate = Gate::new();
    let token = gate.arm_at(Some(relay()), false, 100);
    gate.set_primary(n("en7"));
    let counters = Counters::new();
    let local6: Ipv6Addr = "2001:db8:1::50".parse().unwrap();
    let peer6: Ipv6Addr = "2001:db8:ffff::9".parse().unwrap();
    let udp = {
        let mut l4 = vec![0xc3, 0x50, 0, 53, 0, 12, 0, 0];
        l4.extend_from_slice(b"pong");
        l4
    };
    let cases: [DropCase; 11] = [
        (leak_out(), OUT, "en7", 4, 6, TcpClass::Syn, Reason::TcpOut),
        (
            tcp4(PEER, LOCAL, 443, 50000, SYN | ACK),
            IN,
            "en7",
            4,
            6,
            TcpClass::SynAck,
            Reason::TcpIn,
        ),
        (leak_in(), IN, "en0", 4, 6, TcpClass::AckOnly, Reason::TcpIn),
        (
            eth(
                ETHERTYPE_IPV4,
                &v4(
                    LOCAL,
                    PEER,
                    PROTO_TCP,
                    0x4000,
                    &tcp(50000, 443, ACK, b"data"),
                ),
            ),
            OUT,
            "en0",
            4,
            6,
            TcpClass::Data,
            Reason::TcpOut,
        ),
        (
            tcp4(LOCAL, PEER, 50000, 443, FIN | ACK),
            OUT,
            "awdl0",
            4,
            6,
            TcpClass::Fin,
            Reason::TcpOut,
        ),
        (
            eth(
                ETHERTYPE_IPV6,
                &v6(local6, peer6, PROTO_TCP, &tcp(50000, 443, RST | ACK, b"")),
            ),
            OUT,
            "en7",
            6,
            6,
            TcpClass::Rst,
            Reason::TcpOut,
        ),
        (
            eth(ETHERTYPE_IPV4, &v4(LOCAL, PEER, PROTO_UDP, 0x4000, &udp)),
            OUT,
            "en7",
            4,
            17,
            TcpClass::None,
            Reason::Udp,
        ),
        // A later fragment carries no TCP header.
        (
            eth(
                ETHERTYPE_IPV4,
                &v4(LOCAL, PEER, PROTO_TCP, 0x0010, b"12345678"),
            ),
            OUT,
            "en7",
            4,
            6,
            TcpClass::None,
            Reason::Fragment,
        ),
        // A TCP header cut short by the IP length: its ports decide the
        // verdict, its flags cannot be read.
        (
            eth(
                ETHERTYPE_IPV4,
                &v4(LOCAL, PEER, PROTO_TCP, 0x4000, &[0xc3, 0x50, 1, 0xbb]),
            ),
            OUT,
            "en7",
            4,
            6,
            TcpClass::Other,
            Reason::TcpOut,
        ),
        (
            eth(0x88cc, &[0u8; 40]),
            OUT,
            "en7",
            0,
            0,
            TcpClass::None,
            Reason::NonIp,
        ),
        (
            vec![1, 2, 3],
            OUT,
            "en7",
            0,
            0,
            TcpClass::None,
            Reason::Malformed,
        ),
    ];
    for (k, (frame, direction, name, family, protocol, tcp, reason)) in cases.iter().enumerate() {
        let now = 350 + k as u64;
        assert_eq!(
            filter_packet_with(&gate, &counters, n(name), *direction, frame, || now),
            Verdict::Drop,
            "{k}"
        );
        let (index, entry) = *counters.ring().snapshot().entries.last().unwrap();
        assert_eq!(index, k as u64);
        assert_eq!(
            entry,
            DropRecord {
                arm_seq: token.get() as u32,
                ms: 250 + k as u32,
                iface: iface_code(n(name)),
                class: drop_class(iface_code(n(name)), gate.primary()),
                direction: Direction::from_raw(*direction),
                family: *family,
                protocol: *protocol,
                tcp: *tcp,
                reason: *reason,
            },
            "{k}"
        );
    }
    // An allowed packet reads no clock and writes no record.
    let next = counters.ring().snapshot().next;
    let relay_syn = tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN);
    assert_eq!(
        filter_packet_with(&gate, &counters, n("en7"), OUT, &relay_syn, || panic!(
            "clock read for an allowed packet"
        )),
        Verdict::Allow
    );
    assert_eq!(counters.ring().snapshot().next, next);
    // A clock behind the arm saturates at 0 ms; a re-arm restarts the ms.
    filter_packet_with(&gate, &counters, n("en7"), OUT, &leak_out(), || 10);
    assert_eq!(counters.ring().snapshot().entries.last().unwrap().1.ms, 0);
    let second = gate.arm_at(Some(relay()), false, 1_000);
    filter_packet_with(&gate, &counters, n("en7"), OUT, &leak_out(), || 1_007);
    let last = counters.ring().snapshot().entries.last().unwrap().1;
    assert_eq!((u64::from(last.arm_seq), last.ms), (second.get(), 7));
}

#[test]
fn the_tcp_class_reads_flags_and_payload_from_the_header_lengths() {
    assert_eq!(tcp_class(&tcp(1, 2, SYN, b"")), TcpClass::Syn);
    assert_eq!(tcp_class(&tcp(1, 2, SYN | ACK, b"")), TcpClass::SynAck);
    assert_eq!(tcp_class(&tcp(1, 2, SYN | RST, b"")), TcpClass::Rst);
    assert_eq!(tcp_class(&tcp(1, 2, ACK, b"")), TcpClass::AckOnly);
    assert_eq!(tcp_class(&tcp(1, 2, ACK, b"x")), TcpClass::Data);
    assert_eq!(tcp_class(&tcp(1, 2, FIN | ACK, b"x")), TcpClass::Fin);
    assert_eq!(tcp_class(&tcp(1, 2, 0, b"")), TcpClass::Other);
    assert_eq!(tcp_class(&tcp(1, 2, 0x08, b"payload")), TcpClass::Data);
    assert_eq!(tcp_class(&[0; 13]), TcpClass::Other);
    // A data offset past the segment, or below 20 bytes, is no payload.
    let mut long_header = tcp(1, 2, ACK, b"xxxx");
    long_header[12] = 0x60;
    assert_eq!(tcp_class(&long_header), TcpClass::AckOnly);
    let mut short_offset = tcp(1, 2, ACK, b"");
    short_offset[12] = 0x40;
    assert_eq!(tcp_class(&short_offset), TcpClass::AckOnly);
    for (class, name) in TCP_CLASSES.iter().zip([
        "none", "syn", "syn_ack", "ack_only", "data", "fin", "rst", "other",
    ]) {
        assert_eq!(class.name(), name);
    }
}

#[test]
fn arm_accounting_counts_arms_disarms_and_guarded_time() {
    let gate = Gate::new();
    assert_eq!(gate.arm_stats_at(5), ArmStats::default());
    let first = gate.arm_at(Some(relay()), false, 1_000);
    let stats = gate.arm_stats_at(1_500);
    assert_eq!(
        (
            stats.arm_seq,
            stats.disarms,
            stats.armed_ms_total,
            stats.armed_for_ms
        ),
        (1, 0, 500, Some(500))
    );
    // A re-arm while guarding continues the span and restarts the arm age.
    let second = gate.arm_at(None, false, 2_000);
    let stats = gate.arm_stats_at(2_500);
    assert_eq!(
        (stats.arm_seq, stats.armed_ms_total, stats.armed_for_ms),
        (2, 1_500, Some(500))
    );
    // A superseded token opens nothing and counts nothing.
    assert!(!gate.disarm_at(first, 2_600));
    assert_eq!(gate.arm_stats_at(2_600).disarms, 0);
    assert!(gate.disarm_at(second, 3_000));
    let stats = gate.arm_stats_at(4_000);
    assert_eq!(
        (
            stats.arm_seq,
            stats.disarms,
            stats.armed_ms_total,
            stats.armed_for_ms
        ),
        (2, 1, 2_000, None)
    );
    // A second disarm of the same token is no second Open.
    assert!(!gate.disarm_at(second, 4_100));
    let third = gate.arm_at(None, false, 5_000);
    assert!(gate.disarm_at(third, 5_100));
    let stats = gate.arm_stats_at(9_999);
    assert_eq!(
        (stats.arm_seq, stats.disarms, stats.armed_ms_total),
        (3, 2, 2_100)
    );
    // A clock that went backwards adds nothing.
    let fourth = gate.arm_at(None, false, 8_000);
    assert!(gate.disarm_at(fourth, 7_000));
    assert_eq!(gate.arm_stats_at(9_999).armed_ms_total, 2_100);
    // The real clock: arm and disarm read it, and never fail.
    let real = Gate::new();
    let token = real.arm(None, false);
    assert!(real.arm_stats().armed_for_ms.is_some());
    assert!(real.disarm(token));
    assert_eq!(real.arm_stats().armed_for_ms, None);
    assert!(clock_ms() <= control_clock_ms());
}

#[test]
fn an_open_interval_while_an_epoch_is_applied_is_counted() {
    let gate = Gate::new();
    // The production order: arm, applied, ..., withdrawn, disarm.
    let token = gate.arm(None, false);
    gate.note_applied();
    assert_eq!(gate.arm_stats().applied_epochs, 1);
    gate.note_withdrawn();
    assert!(gate.disarm(token));
    assert_eq!(gate.arm_stats().open_while_applied, 0);
    // A disarm while the epoch is still applied leaves a trace.
    let token = gate.arm(None, false);
    gate.note_applied();
    assert!(gate.disarm(token));
    assert_eq!(gate.arm_stats().open_while_applied, 1);
    gate.note_withdrawn();
    // An epoch applied while the gate is Open leaves one too.
    gate.note_applied();
    assert_eq!(gate.arm_stats().open_while_applied, 2);
    gate.note_withdrawn();
    gate.note_withdrawn();
    assert_eq!(gate.arm_stats().applied_epochs, 0, "saturates at zero");
    // A stale disarm opens nothing, so it counts nothing.
    let token = gate.arm(None, false);
    gate.note_applied();
    assert!(!gate.disarm(ArmToken(token.get() + 1)));
    assert_eq!(gate.arm_stats().open_while_applied, 2);
}

#[test]
fn the_observability_path_never_changes_a_verdict() {
    let gate = armed_gate();
    let pinned = armed_gate();
    pinned.set_primary(n("en0"));
    let counters = Counters::new();
    let frames = [
        leak_out(),
        leak_in(),
        tcp4(LOCAL, RELAY, 50000, RELAY_PORT, SYN),
        tcp4(RELAY, LOCAL, RELAY_PORT, 50000, ACK),
        eth(ETHERTYPE_ARP, &[0, 1, 8, 0, 6, 4, 0, 1]),
        vec![],
        vec![0x45; 30],
    ];
    let (snapshot, _) = gate.snapshot();
    for frame in &frames {
        for name in [n("en0"), n("en7"), n("awdl0"), n("utun2"), n("lo0"), None] {
            for direction in [ANY, IN, OUT, 7] {
                let (expected, _) = verdict(
                    &snapshot,
                    classify_interface(name),
                    Direction::from_raw(direction),
                    frame,
                );
                assert_eq!(
                    filter_packet(&gate, &counters, name, direction, frame),
                    expected
                );
                assert_eq!(
                    filter_packet(&pinned, &counters, name, direction, frame),
                    expected
                );
            }
        }
    }
    // A full or torn ring changes nothing either.
    for slot in 0..RING_SLOTS {
        counters.ring().hold_slot_for_test(slot);
    }
    assert_eq!(
        filter_packet(&gate, &counters, n("en0"), OUT, &leak_out()),
        Verdict::Drop
    );
    assert_eq!(
        filter_packet(&gate, &counters, n("en0"), OUT, &frames[2]),
        Verdict::Allow
    );
}

#[test]
fn the_drop_path_with_its_ring_never_allocates() {
    let gate = armed_gate();
    gate.set_primary(n("en0"));
    let counters = Counters::new();
    let frames = [leak_out(), leak_in(), vec![1, 2, 3], eth(0x88cc, &[0; 40])];
    let names = [
        n("en0"),
        n("awdl0"),
        n("a-name-that-is-hashed-and-long-enough"),
        None,
    ];
    let before = crate::test_alloc::allocations();
    let mut dropped = 0u32;
    for _ in 0..40 {
        for frame in &frames {
            for name in names {
                if filter_packet(&gate, &counters, name, OUT, frame) == Verdict::Drop {
                    dropped += 1;
                }
            }
        }
    }
    let after = crate::test_alloc::allocations();
    assert_eq!(after, before, "the drop path allocated");
    assert!(dropped as usize > RING_SLOTS, "the ring wrapped");
}

#[test]
fn wall_tokens_are_seconds_with_six_fraction_digits() {
    let at = UNIX_EPOCH + std::time::Duration::from_micros(1_800_000_000_250_000);
    assert_eq!(wall_token(at), "1800000000.250000");
    let at = UNIX_EPOCH + std::time::Duration::from_nanos(1_800_000_000_000_000_999);
    assert_eq!(wall_token(at), "1800000000.000000");
    assert_eq!(
        wall_token(UNIX_EPOCH - std::time::Duration::from_secs(1)),
        "0.000000"
    );
}
