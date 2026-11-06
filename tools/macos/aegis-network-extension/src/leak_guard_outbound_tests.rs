//! v29 (S20h) outbound observability of the leak guard over synthetic
//! frames: the outbound drops by class and kind, the marked ones, the ring
//! of outbound drops that no inbound flood can overwrite, and the tunnel and
//! loopback fast path. Documentation addresses only; nothing is sent or
//! captured.
use super::*;
use std::sync::Arc;

const LOCAL: [u8; 4] = [192, 0, 2, 50];
const GATEWAY: [u8; 4] = [192, 0, 2, 1];
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
const PSH: u8 = 0x08;
/// A source port of the marker range (the positive control's sockets bind
/// there), and one outside it.
const MARKED: u16 = MARK_SPORT_FIRST + 3;
const PLAIN: u16 = 50001;
/// XNU's default IPv4 TTL (`net.inet.ip.ttl`), which `tcp_respond` puts on
/// every keepalive, and the TTL the first v29 draft took for its marker.
const DEFTTL: u8 = 64;
const OLD_MARK_TTL: u8 = 77;

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

fn v4(src: [u8; 4], dst: [u8; 4], proto: u8, ttl: u8, fragment: u16, l4: &[u8]) -> Vec<u8> {
    let total = (20 + l4.len()) as u16;
    let mut packet = vec![0x45, 0];
    packet.extend_from_slice(&total.to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&fragment.to_be_bytes());
    packet.extend_from_slice(&[ttl, proto, 0, 0]);
    packet.extend_from_slice(&src);
    packet.extend_from_slice(&dst);
    packet.extend_from_slice(l4);
    packet
}

fn v6(src: Ipv6Addr, dst: Ipv6Addr, next: u8, hop_limit: u8, l4: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x60, 0, 0, 0];
    packet.extend_from_slice(&(l4.len() as u16).to_be_bytes());
    packet.extend_from_slice(&[next, hop_limit]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(l4);
    packet
}

fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![2, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 2];
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// An Ethernet IPv4 TCP segment from the Mac's `sport` to the LAN gateway,
/// with the default TTL.
fn out4(flags: u8, payload: &[u8], sport: u16) -> Vec<u8> {
    eth(
        0x0800,
        &v4(
            LOCAL,
            GATEWAY,
            6,
            DEFTTL,
            0,
            &tcp(sport, 80, flags, payload),
        ),
    )
}

/// An Ethernet IPv4 bare ACK from the Mac's `sport` to the LAN gateway with
/// `ttl`.
fn ack4(sport: u16, ttl: u8) -> Vec<u8> {
    eth(
        0x0800,
        &v4(LOCAL, GATEWAY, 6, ttl, 0, &tcp(sport, 80, ACK, b"")),
    )
}

/// The gateway's UDP datagram to the Mac (the v28 inbound flood's shape).
fn flood() -> Vec<u8> {
    let mut l4 = vec![0x1f, 0x90, 0xc3, 0x51, 0, 0, 0, 0];
    l4.extend_from_slice(&[0xab; 1000]);
    let length = l4.len() as u16;
    l4[4..6].copy_from_slice(&length.to_be_bytes());
    eth(0x0800, &v4(PEER, LOCAL, 17, 64, 0, &l4))
}

fn armed() -> Gate {
    let gate = Gate::new();
    gate.arm_at(Some(relay()), false, 100);
    gate.set_primary(n("en7"));
    gate
}

/// A frame, its raw direction and interface name, and the kind and mark its
/// outbound drop must be counted with (`None`: never an outbound drop).
type OutCase = (Vec<u8>, isize, &'static str, Option<OutKind>, bool);

fn kind_of(table: &OutCounts, class: DropClass, kind: OutKind) -> u64 {
    table[class.slot()][kind.slot()]
}

#[test]
fn outbound_drops_are_counted_by_class_and_kind_and_marked_by_their_source_port() {
    let gate = armed();
    let counters = Counters::new();
    let local6: Ipv6Addr = "2001:db8:1::50".parse().unwrap();
    let gateway6: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
    let udp = {
        let mut l4 = MARKED.to_be_bytes().to_vec();
        l4.extend_from_slice(&[0, 53, 0, 12, 0, 0]);
        l4.extend_from_slice(b"ping");
        l4
    };
    let last = MARK_SPORT_FIRST + MARK_SPORT_COUNT - 1;
    // (frame, direction, interface, kind, marked): every outbound drop is
    // counted once by its kind, and once more when it is TCP from a port of
    // the marker range, whatever its TTL.
    let cases: Vec<OutCase> = vec![
        (out4(SYN, b"", PLAIN), OUT, "en7", Some(OutKind::Syn), false),
        (
            out4(SYN | ACK, b"", PLAIN),
            OUT,
            "en7",
            Some(OutKind::SynAck),
            false,
        ),
        (
            out4(ACK, b"", PLAIN),
            OUT,
            "en7",
            Some(OutKind::AckOnly),
            false,
        ),
        (
            out4(ACK, b"", MARKED),
            OUT,
            "en7",
            Some(OutKind::AckOnly),
            true,
        ),
        (
            out4(ACK | PSH, b"aegis-s20g-presock-0\n", MARKED),
            OUT,
            "en7",
            Some(OutKind::Data),
            true,
        ),
        (
            out4(FIN | ACK, b"", PLAIN),
            OUT,
            "en7",
            Some(OutKind::Fin),
            false,
        ),
        (out4(RST, b"", MARKED), OUT, "en7", Some(OutKind::Rst), true),
        (out4(0, b"", PLAIN), OUT, "en7", Some(OutKind::Other), false),
        // The TTL is no marker: 77 from another port is not marked, and the
        // range's edges are.
        (
            ack4(PLAIN, OLD_MARK_TTL),
            OUT,
            "en7",
            Some(OutKind::AckOnly),
            false,
        ),
        (
            ack4(MARK_SPORT_FIRST, DEFTTL),
            OUT,
            "en7",
            Some(OutKind::AckOnly),
            true,
        ),
        (ack4(last, 1), OUT, "en7", Some(OutKind::AckOnly), true),
        (
            ack4(MARK_SPORT_FIRST - 1, OLD_MARK_TTL),
            OUT,
            "en7",
            Some(OutKind::AckOnly),
            false,
        ),
        (
            ack4(last + 1, DEFTTL),
            OUT,
            "en7",
            Some(OutKind::AckOnly),
            false,
        ),
        // A later fragment of a TCP packet has no header: other, never
        // marked, whatever its bytes.
        (
            eth(
                0x0800,
                &v4(
                    LOCAL,
                    GATEWAY,
                    6,
                    OLD_MARK_TTL,
                    0x0010,
                    &tcp(MARKED, 80, ACK, b""),
                ),
            ),
            OUT,
            "en7",
            Some(OutKind::Other),
            false,
        ),
        // A TCP header too short to hold the flags: other, never marked.
        (
            eth(
                0x0800,
                &v4(
                    LOCAL,
                    GATEWAY,
                    6,
                    DEFTTL,
                    0,
                    &tcp(MARKED, 80, ACK, b"")[..12],
                ),
            ),
            OUT,
            "en7",
            Some(OutKind::Other),
            false,
        ),
        // UDP and ICMP are never marked, from any port and with any TTL.
        (
            eth(0x0800, &v4(LOCAL, GATEWAY, 17, DEFTTL, 0, &udp)),
            OUT,
            "en7",
            Some(OutKind::NonTcp),
            false,
        ),
        (
            eth(
                0x0800,
                &v4(
                    LOCAL,
                    GATEWAY,
                    1,
                    OLD_MARK_TTL,
                    0,
                    &[8, 0, 0, 0, 0, 1, 0, 1],
                ),
            ),
            OUT,
            "en7",
            Some(OutKind::NonTcp),
            false,
        ),
        (
            eth(
                0x86dd,
                &v6(local6, gateway6, 6, DEFTTL, &tcp(MARKED, 443, ACK, b"")),
            ),
            OUT,
            "en7",
            Some(OutKind::AckOnly),
            true,
        ),
        // Non-IP frames (never framed as IP) are non_tcp and never marked.
        (
            eth(0x88cc, &[0xb7; 40]),
            OUT,
            "en7",
            Some(OutKind::NonTcp),
            false,
        ),
        // Another interface: its own class.
        (
            out4(ACK, b"x", MARKED),
            OUT,
            "en0",
            Some(OutKind::Data),
            true,
        ),
        (
            out4(ACK, b"", MARKED),
            OUT,
            "awdl0",
            Some(OutKind::AckOnly),
            true,
        ),
        // Inbound and Any drops are never outbound drops.
        (out4(ACK, b"", MARKED), IN, "en7", None, false),
        (flood(), IN, "en7", None, false),
        (out4(ACK, b"", MARKED), ANY, "en7", None, false),
        (out4(ACK, b"", MARKED), 9, "en7", None, false),
    ];
    let mut kinds = [[0u64; OUT_KINDS.len()]; DROP_CLASSES.len()];
    let mut marked = kinds;
    let mut ring = Vec::new();
    for (k, (frame, direction, name, kind, mark)) in cases.iter().enumerate() {
        let verdict = filter_packet_with(&gate, &counters, n(name), *direction, frame, || {
            100 + k as u64
        });
        assert_eq!(verdict, Verdict::Drop, "case {k}");
        if let Some(kind) = kind {
            let class = drop_class(iface_code(n(name)), gate.primary());
            kinds[class.slot()][kind.slot()] += 1;
            if *mark {
                marked[class.slot()][kind.slot()] += 1;
            }
            ring.push((k as u32, *name, *mark));
        }
    }
    assert_eq!(counters.out_snapshot(), (kinds, marked));
    assert_eq!(kind_of(&kinds, DropClass::Primary, OutKind::AckOnly), 8);
    assert_eq!(kind_of(&marked, DropClass::Primary, OutKind::AckOnly), 4);
    assert_eq!(kind_of(&marked, DropClass::Primary, OutKind::Other), 0);
    assert_eq!(kind_of(&marked, DropClass::Primary, OutKind::NonTcp), 0);
    assert_eq!(kind_of(&marked, DropClass::EnOther, OutKind::Data), 1);
    assert_eq!(kind_of(&marked, DropClass::AwdlLlw, OutKind::AckOnly), 1);
    // The outbound ring holds the outbound drops only, in order, with their
    // mark; the v27 ring every drop.
    let outbound = counters.out_ring().snapshot_marked();
    assert_eq!(outbound.next, ring.len() as u64);
    assert_eq!((outbound.skipped, outbound.torn), (0, 0));
    assert_eq!(outbound.entries.len(), ring.len());
    for ((index, record, mark), (k, name, expected)) in outbound.entries.iter().zip(&ring) {
        assert_eq!(record.direction, Direction::Outbound);
        assert_eq!(record.ms, *k, "ms since the arm at 100");
        assert_eq!(record.iface, iface_code(n(name)));
        assert_eq!(mark, expected, "entry {index}");
    }
    assert_eq!(counters.ring().snapshot().next, cases.len() as u64);
    // The marked table never counts more than all drops of a cell.
    for (all, some) in kinds.iter().flatten().zip(marked.iter().flatten()) {
        assert!(some <= all);
    }
}

#[test]
fn an_inbound_flood_never_evicts_the_outbound_records() {
    let gate = armed();
    let counters = Counters::new();
    for k in 0..10u64 {
        filter_packet_with(
            &gate,
            &counters,
            n("en7"),
            OUT,
            &out4(ACK, b"", MARKED),
            || 1_100 + 4_000 * k,
        );
    }
    // 1300 inbound drops a second for longer than v28's armed span.
    for k in 0..65_000u64 {
        filter_packet_with(&gate, &counters, n("en7"), IN, &flood(), || 50_000 + k);
    }
    let outbound = counters.out_ring().snapshot_marked();
    assert_eq!((outbound.next, outbound.skipped, outbound.torn), (10, 0, 0));
    assert_eq!(
        outbound
            .entries
            .iter()
            .map(|(index, record, marked)| (*index, record.ms, record.tcp, *marked))
            .collect::<Vec<_>>(),
        (0..10u64)
            .map(|k| (k, (1_000 + 4_000 * k) as u32, TcpClass::AckOnly, true))
            .collect::<Vec<_>>()
    );
    // The v27 ring kept only the flood's last 64.
    let ring = counters.ring().snapshot();
    assert_eq!(ring.next, 65_010);
    assert_eq!(ring.entries.len(), RING_SLOTS);
    assert!(ring
        .entries
        .iter()
        .all(|(_, record)| record.direction == Direction::Inbound));
    let (kinds, marked) = counters.out_snapshot();
    assert_eq!(kind_of(&kinds, DropClass::Primary, OutKind::AckOnly), 10);
    assert_eq!(kind_of(&marked, DropClass::Primary, OutKind::AckOnly), 10);
    assert_eq!(kinds.iter().flatten().sum::<u64>(), 10);
    assert_eq!(counters.drop_snapshot()[0], [65_000, 10, 0]);
}

#[test]
fn the_outbound_ring_keeps_the_last_64_outbound_drops_and_wraps() {
    let gate = armed();
    let counters = Counters::new();
    for k in 0..150u64 {
        let sport = if k % 3 == 0 { MARKED } else { PLAIN };
        filter_packet_with(
            &gate,
            &counters,
            n("en7"),
            OUT,
            &out4(ACK, b"", sport),
            || 100 + k,
        );
        filter_packet_with(&gate, &counters, n("en7"), IN, &flood(), || 100 + k);
    }
    let outbound = counters.out_ring().snapshot_marked();
    assert_eq!(
        (outbound.next, outbound.skipped, outbound.torn),
        (150, 0, 0)
    );
    assert_eq!(outbound.entries.len(), RING_SLOTS);
    for (k, (index, record, marked)) in outbound.entries.iter().enumerate() {
        let expected = 86 + k as u64;
        assert_eq!(*index, expected);
        assert_eq!(u64::from(record.ms), expected);
        assert_eq!(*marked, expected.is_multiple_of(3), "{expected}");
    }
}

#[test]
fn a_marked_slot_reads_as_the_same_record_and_unpack_ignores_the_mark() {
    let record = DropRecord {
        arm_seq: 7,
        ms: 41_040,
        iface: iface_code(n("en0")),
        class: DropClass::Primary,
        direction: Direction::Outbound,
        family: 4,
        protocol: 6,
        tcp: TcpClass::AckOnly,
        reason: Reason::TcpOut,
    };
    let ring = DropRing::new();
    ring.record_marked(&record, true);
    ring.record_marked(&record, false);
    ring.record(&record);
    assert_eq!(
        ring.snapshot().entries,
        vec![(0, record), (1, record), (2, record)]
    );
    assert_eq!(
        ring.snapshot_marked().entries,
        vec![(0, record, true), (1, record, false), (2, record, false)]
    );
    let (a, b) = record.pack();
    assert_eq!(b & RECORD_MARKED, 0, "pack never sets the mark");
    assert_eq!(DropRecord::unpack(a, b | RECORD_MARKED), Some(record));
}

#[test]
fn a_torn_or_undecodable_outbound_slot_is_detected_and_never_reported() {
    let gate = armed();
    let counters = Counters::new();
    for k in 0..10u64 {
        filter_packet_with(
            &gate,
            &counters,
            n("en7"),
            OUT,
            &out4(ACK, b"", MARKED),
            || 100 + k,
        );
    }
    let ring = counters.out_ring();
    ring.hold_slot_for_test(3);
    let snapshot = ring.snapshot_marked();
    assert_eq!((snapshot.torn, snapshot.entries.len()), (1, 9));
    assert!(snapshot.entries.iter().all(|(index, _, _)| *index != 3));
    // A writer meeting the held slot skips without waiting.
    for k in 0..64u64 {
        filter_packet_with(
            &gate,
            &counters,
            n("en7"),
            OUT,
            &out4(ACK, b"", PLAIN),
            || 200 + k,
        );
    }
    let snapshot = ring.snapshot_marked();
    assert_eq!((snapshot.next, snapshot.skipped), (74, 1));
    ring.release_slot_for_test(3);
    ring.corrupt_slot_for_test(5);
    let snapshot = ring.snapshot_marked();
    assert_eq!(snapshot.torn, 1);
    assert!(snapshot.entries.iter().all(|(index, _, _)| index % 64 != 5));
    assert!(snapshot.entries.iter().all(|(_, _, marked)| !marked));
}

#[test]
fn concurrent_outbound_writers_never_mix_records_or_marks() {
    // Each writer's records carry its own number in every field and its own
    // mark, so a record mixing two writers' words cannot pass the check.
    let counters = Arc::new(Counters::new());
    let expected = |t: u32, ms: u32| DropRecord {
        arm_seq: t,
        ms,
        iface: iface_code(n(&format!("en{t}"))),
        class: DROP_CLASSES[t as usize % DROP_CLASSES.len()],
        direction: Direction::Outbound,
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
                let snapshot = counters.out_ring().snapshot_marked();
                let mut last = None;
                for (index, entry, marked) in &snapshot.entries {
                    assert!(last < Some(*index), "indices increase");
                    last = Some(*index);
                    assert_eq!(*entry, expected(entry.arm_seq, entry.ms), "mixed record");
                    assert_eq!(*marked, entry.arm_seq.is_multiple_of(2), "mixed mark");
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
                    counters
                        .out_ring()
                        .record_marked(&expected(t, k), t.is_multiple_of(2));
                }
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    stop.store(true, Ordering::Relaxed);
    let checked = reader.join().unwrap();
    let snapshot = counters.out_ring().snapshot_marked();
    assert_eq!(snapshot.next, u64::from(WRITERS * EACH));
    assert_eq!(snapshot.torn, 0, "quiescent: nothing torn");
    assert!(snapshot.entries.len() <= RING_SLOTS);
    for (_, entry, marked) in &snapshot.entries {
        assert_eq!(*entry, expected(entry.arm_seq, entry.ms));
        assert_eq!(*marked, entry.arm_seq.is_multiple_of(2));
    }
    assert!(checked > 0, "the reader saw records");
}

#[test]
fn concurrent_filter_threads_count_every_outbound_drop_under_a_flood() {
    // Two threads send outbound segments (one marked, one not) while two
    // others flood inbound: the outbound tables count each exactly, and the
    // outbound ring holds only outbound records.
    let gate = Arc::new(armed());
    let counters = Arc::new(Counters::new());
    const EACH: u64 = 5_000;
    let threads: Vec<_> = (0..4u8)
        .map(|t| {
            let gate = gate.clone();
            let counters = counters.clone();
            std::thread::spawn(move || {
                let frame = match t {
                    0 => out4(ACK, b"", MARKED),
                    1 => out4(ACK, b"x", PLAIN),
                    _ => flood(),
                };
                let direction = if t < 2 { OUT } else { IN };
                for k in 0..EACH {
                    let verdict =
                        filter_packet_with(&gate, &counters, n("en7"), direction, &frame, || k);
                    assert_eq!(verdict, Verdict::Drop);
                }
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    let (kinds, marked) = counters.out_snapshot();
    assert_eq!(kind_of(&kinds, DropClass::Primary, OutKind::AckOnly), EACH);
    assert_eq!(kind_of(&kinds, DropClass::Primary, OutKind::Data), EACH);
    assert_eq!(kind_of(&marked, DropClass::Primary, OutKind::AckOnly), EACH);
    assert_eq!(marked.iter().flatten().sum::<u64>(), EACH);
    let outbound = counters.out_ring().snapshot_marked();
    assert_eq!(outbound.next, 2 * EACH);
    assert!(outbound.entries.len() as u64 >= RING_SLOTS as u64 - outbound.skipped.min(64));
    for (_, record, mark) in &outbound.entries {
        assert_eq!(record.direction, Direction::Outbound);
        assert_eq!(*mark, record.tcp == TcpClass::AckOnly);
    }
    assert_eq!(counters.drop_snapshot()[0], [2 * EACH, 2 * EACH, 0]);
}

/// Frames of every class the filter sees.
fn corpus() -> Vec<Vec<u8>> {
    let local6: Ipv6Addr = "2001:db8:1::50".parse().unwrap();
    let gateway6: Ipv6Addr = "fe80::1".parse().unwrap();
    vec![
        out4(SYN, b"", PLAIN),
        out4(ACK, b"", MARKED),
        out4(ACK | PSH, b"data", MARKED),
        out4(RST, b"", PLAIN),
        eth(
            0x0800,
            &v4(
                LOCAL,
                RELAY,
                6,
                OLD_MARK_TTL,
                0,
                &tcp(MARKED, RELAY_PORT, ACK, b""),
            ),
        ),
        eth(
            0x0800,
            &v4(
                RELAY,
                LOCAL,
                6,
                OLD_MARK_TTL,
                0,
                &tcp(RELAY_PORT, MARKED, ACK, b""),
            ),
        ),
        eth(
            0x0800,
            &v4(LOCAL, GATEWAY, 6, OLD_MARK_TTL, 0x0010, &[0; 16]),
        ),
        ack4(PLAIN, OLD_MARK_TTL),
        flood(),
        eth(
            0x86dd,
            &v6(local6, gateway6, 6, DEFTTL, &tcp(MARKED, 443, ACK, b"")),
        ),
        eth(
            0x86dd,
            &v6(gateway6, local6, 58, 255, &[135, 0, 0, 0, 0, 0, 0, 0]),
        ),
        eth(0x0806, &[0, 1, 8, 0, 6, 4, 0, 1]),
        eth(0x88cc, &[OLD_MARK_TTL; 40]),
        vec![],
        vec![0x45],
        v4(LOCAL, GATEWAY, 6, DEFTTL, 0, &tcp(MARKED, 80, ACK, b"")),
    ]
}

#[test]
fn outbound_counting_never_changes_a_verdict_and_never_allocates() {
    let names = [n("en7"), n("en0"), n("awdl0"), n("utun3"), n("lo0"), None];
    let frames = corpus();
    for udp in [false, true] {
        let gate = Gate::new();
        gate.arm(Some(relay()), udp);
        gate.set_primary(n("en7"));
        let (snapshot, _) = gate.snapshot();
        let counters = Counters::new();
        for frame in &frames {
            for name in names {
                for direction in [ANY, IN, OUT, 9] {
                    let expected = verdict(
                        &snapshot,
                        classify_interface(name),
                        Direction::from_raw(direction),
                        frame,
                    )
                    .0;
                    assert_eq!(
                        filter_packet(&gate, &counters, name, direction, frame),
                        expected
                    );
                }
            }
        }
        let before = crate::test_alloc::allocations();
        let mut dropped = 0u32;
        for frame in &frames {
            for name in names {
                for direction in [ANY, IN, OUT] {
                    if filter_packet(&gate, &counters, name, direction, frame) == Verdict::Drop {
                        dropped += 1;
                    }
                }
            }
        }
        let after = crate::test_alloc::allocations();
        assert_eq!(after, before, "the per-packet path allocated");
        assert!(dropped > 0);
        assert!(counters
            .out_ring()
            .snapshot_marked()
            .entries
            .iter()
            .any(|(_, _, m)| *m));
    }
}

#[test]
fn tunnel_and_loopback_packets_read_only_the_guarding_bit() {
    let frames = corpus();
    let at = |counters: &Counters, reason: Reason| counters.snapshot()[reason.index().unwrap()];
    for (name, reason) in [
        ("utun3", Reason::TunnelIface),
        ("ipsec0", Reason::TunnelIface),
        ("lo0", Reason::LoopbackIface),
    ] {
        // Open: allowed and never counted, as before.
        let gate = Gate::new();
        let counters = Counters::new();
        for frame in &frames {
            for direction in [ANY, IN, OUT] {
                assert_eq!(
                    filter_packet(&gate, &counters, n(name), direction, frame),
                    Verdict::Allow
                );
            }
        }
        assert_eq!(counters.snapshot(), [0; COUNTED.len()], "{name}");
        // Guarding: allowed and counted by the interface reason, as before;
        // nothing else is counted and no ring is written.
        let gate = armed();
        let counters = Counters::new();
        for frame in &frames {
            for direction in [ANY, IN, OUT] {
                assert_eq!(
                    filter_packet(&gate, &counters, n(name), direction, frame),
                    Verdict::Allow
                );
            }
        }
        let total = (frames.len() * 3) as u64;
        assert_eq!(at(&counters, reason), total, "{name}");
        assert_eq!(counters.snapshot().iter().sum::<u64>(), total);
        assert_eq!(counters.ring().snapshot().next, 0);
        assert_eq!(counters.out_ring().snapshot().next, 0);
        // A writer paused mid-write: the guarded path reads it torn and
        // fails closed; a tunnel packet is still allowed and counted, and
        // (v29) no torn snapshot is counted for it.
        gate.hold_write_for_test();
        let counters = Counters::new();
        assert_eq!(
            filter_packet(&gate, &counters, n(name), OUT, &frames[1]),
            Verdict::Allow
        );
        assert_eq!(at(&counters, reason), 1);
        assert_eq!(at(&counters, Reason::TornSnapshot), 0);
        assert_eq!(
            filter_packet(&gate, &counters, n("en0"), OUT, &frames[4]),
            Verdict::Drop,
            "the relay flow fails closed on a torn read"
        );
        assert_eq!(at(&counters, Reason::TornSnapshot), 1);
        gate.release_write_for_test();
    }
}

/// v29 measurement harness (run with `--ignored --nocapture`): the time a
/// tunnel packet takes on the v29 fast path against the full snapshot and
/// verdict it took before, on this machine. Never part of a pass.
#[test]
#[ignore]
fn measure_the_tunnel_fast_path() {
    use std::time::Instant;
    const ROUNDS: u32 = 2_000_000;
    let gate = armed();
    let counters = Counters::new();
    let frame = eth(
        0x0800,
        &v4(
            LOCAL,
            RELAY,
            6,
            64,
            0,
            &tcp(50000, RELAY_PORT, ACK, &[0; 1200]),
        ),
    );
    let name = n("utun4");
    let started = Instant::now();
    for _ in 0..ROUNDS {
        std::hint::black_box(filter_packet(
            &gate,
            &counters,
            std::hint::black_box(name),
            OUT,
            &frame,
        ));
    }
    let fast = started.elapsed();
    let started = Instant::now();
    for _ in 0..ROUNDS {
        // What the v28 path did for the same packet: the snapshot, then the
        // verdict, then the count.
        let (snapshot, torn, _) = gate.read();
        if torn {
            counters.count(Reason::TornSnapshot);
        }
        let (verdict, reason) = verdict(
            &snapshot,
            classify_interface(std::hint::black_box(name)),
            Direction::Outbound,
            &frame,
        );
        counters.count(reason);
        std::hint::black_box(verdict);
    }
    let full = started.elapsed();
    println!(
        "tunnel packet: fast path {:.1} ns, v28 path {:.1} ns ({} rounds)",
        fast.as_nanos() as f64 / f64::from(ROUNDS),
        full.as_nanos() as f64 / f64::from(ROUNDS),
        ROUNDS
    );
}

/// S20h review: XNU sends a socket's keepalives through `tcp_respond`
/// (`tcp_timer.c` TCPT_KEEP, `tcp_send_keep_alive`), which builds each from
/// the connection's template, its addresses and ports, as a bare ACK with
/// `seq = snd_una - 1` and no payload, and sets an IPv4 packet's TTL to the
/// system default (`ip_defttl`, 64), never the socket's `IP_TTL`. The
/// positive control's keepalive so built, from a port of the marker range,
/// must be a marked drop; the same bare ACK from a port outside the range is
/// not, whatever TTL the socket set. (The literal ports keep this test
/// independent of the marker's constants.)
#[test]
fn an_xnu_keepalive_of_a_marked_socket_is_a_marked_drop() {
    let gate = armed();
    let keepalive = |sport: u16, ttl: u8| {
        let mut l4 = tcp(sport, 80, ACK, b"");
        // seq = snd_una - 1 (snd_una 0x1000), ack = rcv_nxt.
        l4[4..8].copy_from_slice(&0x0fffu32.to_be_bytes());
        l4[8..12].copy_from_slice(&0x2000u32.to_be_bytes());
        eth(0x0800, &v4(LOCAL, GATEWAY, 6, ttl, 0x4000, &l4))
    };
    for (sport, ttl, expected) in [
        (47_001, 64, true),
        (47_000, 64, true),
        (47_031, 64, true),
        (49_200, 77, false),
        (49_200, 64, false),
        (46_999, 77, false),
        (47_032, 77, false),
    ] {
        let counters = Counters::new();
        let verdict = filter_packet_with(
            &gate,
            &counters,
            n("en7"),
            OUT,
            &keepalive(sport, ttl),
            || 4_100,
        );
        assert_eq!(verdict, Verdict::Drop, "{sport}/{ttl}");
        let (kinds, marked) = counters.out_snapshot();
        assert_eq!(kind_of(&kinds, DropClass::Primary, OutKind::AckOnly), 1);
        assert_eq!(
            kind_of(&marked, DropClass::Primary, OutKind::AckOnly),
            u64::from(expected),
            "{sport}/{ttl}"
        );
        let ring = counters.out_ring().snapshot_marked();
        assert_eq!(ring.entries.len(), 1);
        let (_, record, mark) = &ring.entries[0];
        assert_eq!(
            (record.tcp, record.ms, *mark),
            (TcpClass::AckOnly, 4_000, expected)
        );
    }
}

/// The positive control's helper binds its sockets in the provider's marker
/// range, the reviews count by the same range, and the controls keep the
/// fresh probes' ports out of it.
#[test]
fn the_helpers_marker_ports_are_the_providers() {
    let probe = include_str!("../harness/net_probe.py");
    let review = include_str!("../harness/leak_review.py");
    let controls = include_str!("../harness/controls.sh");
    for (source, first, count) in [
        (
            probe,
            "PRESOCK_MARK_SPORT_FIRST = ",
            "PRESOCK_MARK_SPORT_COUNT = ",
        ),
        (review, "MARK_SPORT_FIRST = ", "MARK_SPORT_COUNT = "),
        (controls, "PS_MARK_SPORT_FIRST=", "PS_MARK_SPORT_COUNT="),
    ] {
        for line in [
            format!("\n{first}{MARK_SPORT_FIRST}\n"),
            format!("\n{count}{MARK_SPORT_COUNT}\n"),
        ] {
            assert!(source.contains(&line), "{line}");
        }
    }
    let first = std::hint::black_box(MARK_SPORT_FIRST);
    let count = std::hint::black_box(MARK_SPORT_COUNT);
    // Above the reserved ports, below the ephemeral range (49152) and the
    // fresh probes' default base (47100); room for 4 sockets on 4 ifaces.
    assert!(first > 1023 && u32::from(first) + u32::from(count) <= 47_100);
    assert!(controls.contains("PC_SPORT_BASE=${PC_SPORT_BASE:-47100}"));
    assert!(count >= 16);
    assert!(marked_sport(first) && marked_sport(first + count - 1));
    assert!(!marked_sport(first - 1) && !marked_sport(first + count));
    assert!(!marked_sport(0) && !marked_sport(u16::MAX));
}
