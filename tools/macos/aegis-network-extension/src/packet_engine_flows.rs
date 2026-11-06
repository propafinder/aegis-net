//! B-06 S16o: the TCP flows a session's shared engine answered, and the
//! resets the epoch's next session sends for the ones that session's loss
//! orphaned.
//!
//! Installed v24 (r13) lost its session 1.1 s into a cold pool ramp
//! (`capture_lease_expired`). The lost engine had acknowledged
//! tcp_echo_v4's request while that flow waited for a pool stream, so the
//! app had nothing left to retransmit: the rebuilt engine never saw the
//! connection and the probe hung for its whole 10 s. A lost session's
//! engine cannot reset its flows itself (its lease has lapsed and its
//! bridge is sealed), so each device records the flows it answered and
//! hands them to the epoch's `FlowLedger` when it ends; the next session's
//! device resets each one towards the app (RST|ACK at the sequence the app
//! expects next), a few per engine batch and only while its packetFlow
//! output has room, and the app's connection fails at once instead.
//! Addresses stay in memory: nothing here is logged but counts.
//!
//! B-06 S20g (v28): the flows the engine answered are also logged by the
//! class of their destination port (`OpenLog`), address free, so the
//! window can tell that a probe bound to a physical interface was answered
//! by this engine inside the tunnel (the v27 positive control's probes
//! connected in 6-7 ms and no capture held their SYNs; the sampled
//! `flow_open` lines cannot attribute single flows).
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime},
};

/// The flows one device tracks at most (the engine serves up to twice its
/// 512 `max_flows` sockets); past this a new flow is not tracked.
pub(crate) const MAX_TRACKED_FLOWS: usize = 2048;
/// The orphaned flows an epoch's ledger holds at most.
pub(crate) const MAX_ORPHANS: usize = 2048;
/// The resets a device sends per engine batch at most.
pub(crate) const RESETS_PER_BATCH: usize = 8;
/// A device sends resets only while its packetFlow output queue (128
/// frames, `bridge::MAX_PACKETS`; a full output drops and counts) holds
/// fewer frames than this. A rebuilt session's output is written only once it is
/// swapped in, so resets queued before that wait at most this many.
pub(crate) const RESET_OUTPUT_ROOM: usize = 32;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

/// One TCP segment's header fields, read from an IPv4 or IPv6 packet. IPv4
/// fragments past the first and IPv6 packets with extension headers are not
/// read (the engine reassembles or drops them).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Segment {
    pub(crate) src: IpAddr,
    pub(crate) dst: IpAddr,
    pub(crate) sport: u16,
    pub(crate) dport: u16,
    pub(crate) seq: u32,
    pub(crate) ack: u32,
    pub(crate) flags: u8,
    pub(crate) payload: u32,
}

impl Segment {
    /// The segment opens a connection: SYN, with ACK and RST clear.
    pub(crate) fn opens(&self) -> bool {
        self.flags & (SYN | ACK | RST) == SYN
    }

    /// The sequence number just past this segment (its SYN and FIN count).
    fn end(&self) -> u32 {
        let controls = u32::from(self.flags & SYN != 0) + u32::from(self.flags & FIN != 0);
        self.seq.wrapping_add(self.payload).wrapping_add(controls)
    }
}

pub(crate) fn segment(packet: &[u8]) -> Option<Segment> {
    let (src, dst, offset, end) = match packet.first()? >> 4 {
        4 => {
            let header = packet.get(..20)?;
            let fragment = u16::from_be_bytes([header[6], header[7]]) & 0x1fff;
            if fragment != 0 || header[9] != 6 {
                return None;
            }
            let src: [u8; 4] = header[12..16].try_into().ok()?;
            let dst: [u8; 4] = header[16..20].try_into().ok()?;
            let total = usize::from(u16::from_be_bytes([header[2], header[3]]));
            (
                IpAddr::from(src),
                IpAddr::from(dst),
                usize::from(header[0] & 15) * 4,
                total,
            )
        }
        6 => {
            let header = packet.get(..40)?;
            if header[6] != 6 {
                return None;
            }
            let src: [u8; 16] = header[8..24].try_into().ok()?;
            let dst: [u8; 16] = header[24..40].try_into().ok()?;
            let payload = usize::from(u16::from_be_bytes([header[4], header[5]]));
            (IpAddr::from(src), IpAddr::from(dst), 40, 40 + payload)
        }
        _ => return None,
    };
    if offset < 20 {
        return None;
    }
    let tcp = packet.get(offset..end.min(packet.len()))?;
    let data = usize::from(*tcp.get(12)? >> 4) * 4;
    if data < 20 || data > tcp.len() {
        return None;
    }
    let word = |at: usize| u32::from_be_bytes([tcp[at], tcp[at + 1], tcp[at + 2], tcp[at + 3]]);
    Some(Segment {
        src,
        dst,
        sport: u16::from_be_bytes([tcp[0], tcp[1]]),
        dport: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: word(4),
        ack: word(8),
        flags: tcp[13],
        payload: u32::try_from(tcp.len() - data).ok()?,
    })
}

/// `a` comes after `b` in sequence space.
fn after(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// One connection, from the app's side.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    app: IpAddr,
    app_port: u16,
    remote: IpAddr,
    remote_port: u16,
}

#[derive(Clone, Copy, Debug)]
struct Seqs {
    /// The sequence number the engine expects from the app next.
    app_next: u32,
    /// The one the app expects from the engine next, once the engine
    /// answered the SYN.
    engine_next: Option<u32>,
    app_fin: bool,
    engine_fin: bool,
}

/// The TCP flows one device saw open, from the app's SYN on; a RST either
/// way, or a FIN both ways, ends one.
#[derive(Default)]
pub(crate) struct Flows {
    map: HashMap<FlowKey, Seqs>,
}

impl Flows {
    /// A segment from the app, delivered to the engine.
    pub(crate) fn app_sent(&mut self, segment: &Segment) {
        let key = FlowKey {
            app: segment.src,
            app_port: segment.sport,
            remote: segment.dst,
            remote_port: segment.dport,
        };
        if segment.flags & RST != 0 {
            self.map.remove(&key);
            return;
        }
        if segment.opens() {
            if !self.map.contains_key(&key) && !self.room() {
                return;
            }
            self.map.insert(
                key,
                Seqs {
                    app_next: segment.end(),
                    engine_next: None,
                    app_fin: false,
                    engine_fin: false,
                },
            );
            return;
        }
        let Some(seqs) = self.map.get_mut(&key) else {
            return;
        };
        if after(segment.end(), seqs.app_next) {
            seqs.app_next = segment.end();
        }
        seqs.app_fin |= segment.flags & FIN != 0;
        if seqs.app_fin && seqs.engine_fin {
            self.map.remove(&key);
        }
    }

    /// A segment the engine sent to the app. S20g: true when it is the
    /// engine's first SYN-ACK of a tracked flow (the engine answered it).
    pub(crate) fn engine_sent(&mut self, segment: &Segment) -> bool {
        let key = FlowKey {
            app: segment.dst,
            app_port: segment.dport,
            remote: segment.src,
            remote_port: segment.sport,
        };
        if segment.flags & RST != 0 {
            self.map.remove(&key);
            return false;
        }
        let Some(seqs) = self.map.get_mut(&key) else {
            return false;
        };
        let mut answered = false;
        match seqs.engine_next {
            Some(next) if !after(segment.end(), next) => {}
            Some(_) => seqs.engine_next = Some(segment.end()),
            // Only its SYN-ACK starts the engine's side.
            None if segment.flags & (SYN | ACK) == SYN | ACK => {
                seqs.engine_next = Some(segment.end());
                answered = true;
            }
            None => return false,
        }
        seqs.engine_fin |= segment.flags & FIN != 0;
        if seqs.app_fin && seqs.engine_fin {
            self.map.remove(&key);
        }
        answered
    }

    pub(crate) fn contains(&self, key: &FlowKey) -> bool {
        self.map.contains_key(key)
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.map.len()
    }

    /// Room for one more flow: a flow the engine never answered gives way.
    fn room(&mut self) -> bool {
        if self.map.len() < MAX_TRACKED_FLOWS {
            return true;
        }
        let unanswered = self
            .map
            .iter()
            .find(|(_, seqs)| seqs.engine_next.is_none())
            .map(|(key, _)| *key);
        unanswered.is_some_and(|key| self.map.remove(&key).is_some())
    }

    /// The flows the engine answered, as the app last saw them.
    fn answered(&mut self) -> impl Iterator<Item = Orphan> + '_ {
        self.map.drain().filter_map(|(key, seqs)| {
            Some(Orphan {
                key,
                seq: seqs.engine_next?,
                ack: seqs.app_next,
            })
        })
    }
}

/// A flow a lost session's engine answered and never closed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Orphan {
    key: FlowKey,
    seq: u32,
    ack: u32,
}

impl Orphan {
    /// RST|ACK from the remote end to the app, at the sequence number the
    /// app expects next.
    pub(crate) fn reset(&self) -> Option<Vec<u8>> {
        let key = &self.key;
        let mut tcp = [0u8; 20];
        tcp[0..2].copy_from_slice(&key.remote_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&key.app_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&self.seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&self.ack.to_be_bytes());
        tcp[12] = 0x50;
        tcp[13] = RST | ACK;
        let mut packet = match (key.remote, key.app) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut ip = [0u8; 20];
                ip[0] = 0x45;
                ip[2..4].copy_from_slice(&40u16.to_be_bytes());
                ip[6] = 0x40;
                ip[8] = 64;
                ip[9] = 6;
                ip[12..16].copy_from_slice(&src.octets());
                ip[16..20].copy_from_slice(&dst.octets());
                let sum = checksum(&[&ip]);
                ip[10..12].copy_from_slice(&sum.to_be_bytes());
                let pseudo = [&src.octets()[..], &dst.octets(), &[0, 6, 0, 20]].concat();
                let sum = checksum(&[&pseudo, &tcp]);
                tcp[16..18].copy_from_slice(&sum.to_be_bytes());
                ip.to_vec()
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let mut ip = [0u8; 40];
                ip[0] = 0x60;
                ip[4..6].copy_from_slice(&20u16.to_be_bytes());
                ip[6] = 6;
                ip[7] = 64;
                ip[8..24].copy_from_slice(&src.octets());
                ip[24..40].copy_from_slice(&dst.octets());
                let pseudo =
                    [&src.octets()[..], &dst.octets(), &[0, 0, 0, 20, 0, 0, 0, 6]].concat();
                let sum = checksum(&[&pseudo, &tcp]);
                tcp[16..18].copy_from_slice(&sum.to_be_bytes());
                ip.to_vec()
            }
            _ => return None,
        };
        packet.extend_from_slice(&tcp);
        Some(packet)
    }
}

/// The internet checksum of `parts`, each of even length but the last.
pub(crate) fn checksum(parts: &[&[u8]]) -> u16 {
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

/// The epoch's orphaned flows: every session's device hands its answered
/// flows here as it ends, and the next one's resets them.
#[derive(Clone, Default)]
pub(crate) struct FlowLedger(Arc<Ledger>);

#[derive(Default)]
struct Ledger {
    orphans: Mutex<Vec<Orphan>>,
    pending: AtomicUsize,
    reset: AtomicUsize,
}

impl FlowLedger {
    /// `flows` ended with their engine.
    pub(crate) fn orphan(&self, flows: &mut Flows) {
        let mut orphans = self
            .0
            .orphans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let room = MAX_ORPHANS.saturating_sub(orphans.len());
        orphans.extend(flows.answered().take(room));
        self.0.pending.store(orphans.len(), Ordering::Release);
    }

    /// Up to `n` orphans, taken; one whose connection `live` already serves
    /// is dropped.
    pub(crate) fn take(&self, n: usize, live: impl Fn(&FlowKey) -> bool) -> Vec<Orphan> {
        if self.0.pending.load(Ordering::Acquire) == 0 {
            return Vec::new();
        }
        let mut orphans = self
            .0
            .orphans
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut taken = Vec::with_capacity(n.min(orphans.len()));
        while taken.len() < n {
            let Some(orphan) = orphans.pop() else {
                break;
            };
            if !live(&orphan.key) {
                taken.push(orphan);
            }
        }
        self.0.pending.store(orphans.len(), Ordering::Release);
        taken
    }

    pub(crate) fn pending(&self) -> usize {
        self.0.pending.load(Ordering::Acquire)
    }

    /// `n` resets were sent.
    pub(crate) fn note_reset(&self, n: usize) {
        self.0.reset.fetch_add(n, Ordering::AcqRel);
    }

    /// The resets sent so far.
    #[cfg(test)]
    pub(crate) fn resets(&self) -> usize {
        self.0.reset.load(Ordering::Acquire)
    }
}

/// S20g: the class of a flow's destination port in `engine_flow_open`.
/// `discard` is port 9, the positive control's fresh bound probes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PortClass {
    Discard,
    Dns,
    Web,
    /// Any other port below 1024.
    Low,
    High,
}

impl PortClass {
    pub(crate) const ALL: [PortClass; 5] = [
        PortClass::Discard,
        PortClass::Dns,
        PortClass::Web,
        PortClass::Low,
        PortClass::High,
    ];

    pub(crate) fn of(port: u16) -> Self {
        match port {
            9 => PortClass::Discard,
            53 => PortClass::Dns,
            80 | 443 | 8080 => PortClass::Web,
            0..=1023 => PortClass::Low,
            _ => PortClass::High,
        }
    }

    pub(crate) const fn code(self) -> &'static str {
        match self {
            PortClass::Discard => "class:discard",
            PortClass::Dns => "class:dns",
            PortClass::Web => "class:web",
            PortClass::Low => "class:low",
            PortClass::High => "class:high",
        }
    }

    fn index(self) -> usize {
        self as usize
    }
}

/// S20g: a class other than `discard` is logged at most this often.
pub(crate) const OPEN_CLASS_LOG_EVERY: Duration = Duration::from_secs(1);
/// S20g: `discard` opens one device logs at most, one line each.
pub(crate) const DISCARD_LINES: u64 = 64;

/// S20g (v28): the flows one device's engine answered, by the class of
/// their destination port, logged as `engine_flow_open class:<c> n:<k>
/// wall:<T>`: `k` the class's answered flows of this device so far, `T`
/// the wall-clock time of the line (`leak_guard::wall_token`). Every
/// `discard` flow is logged (the first `DISCARD_LINES`), so a window can
/// count its probes between two wall times; any other class at most once
/// per `OPEN_CLASS_LOG_EVERY`, its `n` covering the flows held back. No
/// address and no port: only the class.
#[derive(Debug, Default)]
pub(crate) struct OpenLog {
    opens: [u64; PortClass::ALL.len()],
    last: [Option<Instant>; PortClass::ALL.len()],
    #[cfg(test)]
    lines: Vec<String>,
}

impl OpenLog {
    /// The engine answered a flow to `port` at `now`.
    pub(crate) fn answered(&mut self, port: u16, now: Instant) {
        let class = PortClass::of(port);
        let at = class.index();
        self.opens[at] = self.opens[at].saturating_add(1);
        let due = match class {
            PortClass::Discard => self.opens[at] <= DISCARD_LINES,
            _ => self.last[at]
                .is_none_or(|last| now.saturating_duration_since(last) >= OPEN_CLASS_LOG_EVERY),
        };
        if !due {
            return;
        }
        self.last[at] = Some(now);
        let count = format!("n:{}", self.opens[at]);
        let wall = format!("wall:{}", crate::leak_guard::wall_token(SystemTime::now()));
        #[cfg(all(target_os = "macos", feature = "apple"))]
        crate::apple::log_fields("engine_flow_open", &[class.code(), &count, &wall]);
        #[cfg(test)]
        self.lines
            .push(format!("engine_flow_open {} {count} {wall}", class.code()));
    }

    /// Test-only: every line logged so far.
    #[cfg(test)]
    pub(crate) fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// Log `sent` resets of orphaned flows, `left` still to send: counts only,
/// each its own stable field (v41: both in one field, with a space, were
/// logged as `unstable_code` since S16o).
pub(crate) fn log_resets(sent: usize, left: usize) {
    #[cfg(all(target_os = "macos", feature = "apple"))]
    crate::apple::log_fields(
        "flow_orphans_reset",
        &[&format!("n:{sent}"), &format!("left:{left}")],
    );
    #[cfg(not(all(target_os = "macos", feature = "apple")))]
    let _ = (sent, left);
}
