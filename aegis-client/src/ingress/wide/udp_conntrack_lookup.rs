//! One fresh, complete conntrack lookup per captured datagram.
//!
//! The 400ms cutoff and bounded table/dump limits are new recovery policy.
//! They do not change the UDP receive or relay idle clocks. Kernel syscall
//! scheduling can exceed a requested wait; every late result is refused.

use super::udp_conntrack::{self, Lookup};
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub(super) const LOOKUP_TIMEOUT: Duration = Duration::from_millis(400);
pub(super) const MAX_LOOKUP_BYTES: usize = 1 << 20;
const MAX_LOOKUP_MESSAGES: usize = 8192;
const RECEIVE_BYTES: usize = 1 << 17;

pub(super) struct Control<'a> {
    deadline: Instant,
    stop: &'a AtomicBool,
}

impl<'a> Control<'a> {
    pub(super) fn new(stop: &'a AtomicBool) -> Self {
        let now = Instant::now();
        Self {
            deadline: now.checked_add(LOOKUP_TIMEOUT).unwrap_or(now),
            stop,
        }
    }

    pub(super) fn remaining(&self) -> Option<Duration> {
        if self.stop.load(Ordering::SeqCst) {
            return None;
        }
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
    }

    pub(super) fn permitted(&self) -> bool {
        self.remaining().is_some()
    }

    #[cfg(test)]
    fn expired(stop: &'a AtomicBool) -> Self {
        Self {
            deadline: Instant::now(),
            stop,
        }
    }
}

pub(super) enum ProcSnapshot {
    Unavailable,
    Complete(Vec<u8>),
    Refused,
}

fn destination(result: Lookup) -> Option<SocketAddrV4> {
    match result {
        Lookup::Found(dst) => Some(dst),
        Lookup::Absent | Lookup::Refused => None,
    }
}

/// The native fallback runs only after a complete absent table or unavailable
/// proc interface, never after partial input, known ambiguity or cancellation.
pub(super) fn resolve_sources(
    peer: SocketAddrV4,
    control: &Control<'_>,
    read_proc: impl FnOnce() -> ProcSnapshot,
    native: impl FnOnce(SocketAddrV4) -> Lookup,
) -> Option<SocketAddrV4> {
    if !control.permitted() {
        return None;
    }
    let snapshot = read_proc();
    if !control.permitted() {
        return None;
    }
    let table = match &snapshot {
        ProcSnapshot::Unavailable => None,
        ProcSnapshot::Refused => return None,
        ProcSnapshot::Complete(bytes) => {
            if bytes.len() > MAX_LOOKUP_BYTES {
                return None;
            }
            let Ok(table) = std::str::from_utf8(bytes) else {
                return None;
            };
            Some(table)
        }
    };
    let result = udp_conntrack::resolve_proc_or_else(table, peer, |peer| {
        if control.permitted() {
            destination(native(peer))
        } else {
            None
        }
    });
    control.permitted().then_some(result).flatten()
}

// RESOLVER_ROLE_START
#[derive(Default)]
pub(super) struct Resolver {}

impl Resolver {
    pub(super) fn resolve(
        &mut self,
        peer: SocketAddr,
        _now: Instant,
        control: &Control<'_>,
        lookup: impl FnOnce(SocketAddrV4, &Control<'_>) -> Option<SocketAddrV4>,
    ) -> Option<SocketAddr> {
        let SocketAddr::V4(peer) = peer else {
            return None;
        };
        if !control.permitted() {
            return None;
        }
        let result = lookup(peer, control);
        control
            .permitted()
            .then_some(result)
            .flatten()
            .map(SocketAddr::V4)
    }
}
// RESOLVER_ROLE_END

pub(super) struct Received {
    pub(super) len: usize,
    pub(super) kernel_peer: bool,
    pub(super) truncated: bool,
}

enum Scan {
    More,
    Complete(Lookup),
    Refused,
}

/// Owns the receive buffer and one accumulator. Neither a receive wake nor an
/// unrelated record creates a new deadline or publishes an early destination.
pub(super) fn lookup_dump(
    peer: SocketAddrV4,
    sequence: u32,
    control: &Control<'_>,
    mut receive: impl FnMut(&mut [u8], &Control<'_>) -> Result<Received, ()>,
) -> Lookup {
    if !control.permitted() {
        return Lookup::Refused;
    }
    let mut buffer = vec![0u8; RECEIVE_BYTES];
    let mut received_bytes = 0usize;
    let mut scan = Dump::new(peer, sequence);
    loop {
        if !control.permitted() {
            return Lookup::Refused;
        }
        let Ok(received) = receive(&mut buffer, control) else {
            return Lookup::Refused;
        };
        if !control.permitted()
            || !received.kernel_peer
            || received.truncated
            || received.len == 0
            || received.len > buffer.len()
        {
            return Lookup::Refused;
        }
        let Some(total) = received_bytes.checked_add(received.len) else {
            return Lookup::Refused;
        };
        if total > MAX_LOOKUP_BYTES {
            return Lookup::Refused;
        }
        received_bytes = total;
        match scan.feed(&buffer[..received.len]) {
            Scan::More => {}
            Scan::Refused => return Lookup::Refused,
            Scan::Complete(result) => {
                return if control.permitted() {
                    result
                } else {
                    Lookup::Refused
                };
            }
        }
    }
}

// SCANNER_ROLE_START
struct Dump {
    peer: SocketAddrV4,
    sequence: u32,
    messages: usize,
    found: Option<SocketAddrV4>,
}

impl Dump {
    fn new(peer: SocketAddrV4, sequence: u32) -> Self {
        Self {
            peer,
            sequence,
            messages: 0,
            found: None,
        }
    }

    fn feed(&mut self, buffer: &[u8]) -> Scan {
        let mut offset = 0usize;
        let mut done = false;
        while offset < buffer.len() {
            if done || buffer.len() - offset < 16 {
                return Scan::Refused;
            }
            let length = u32_ne(&buffer[offset..]) as usize;
            if length < 16 || length > buffer.len() - offset {
                return Scan::Refused;
            }
            self.messages += 1;
            if self.messages > MAX_LOOKUP_MESSAGES {
                return Scan::Refused;
            }
            let kind = u16_ne(&buffer[offset + 4..]);
            let flags = u16_ne(&buffer[offset + 6..]);
            let sequence = u32_ne(&buffer[offset + 8..]);
            if sequence != self.sequence || flags & 0x10 != 0 {
                return Scan::Refused;
            }
            let payload = &buffer[offset + 16..offset + length];
            match kind {
                3 => {
                    // NLMSG_DONE may carry a signed dump completion status.
                    if !payload.is_empty() && (payload.len() != 4 || u32_ne(payload) != 0) {
                        return Scan::Refused;
                    }
                    done = true;
                }
                0x100 => {
                    // NFNL_SUBSYS_CTNETLINK / IPCTNL_MSG_CT_NEW, nfgenmsg IPv4.
                    if flags & 2 == 0 || payload.len() < 4 || payload[0] != 2 {
                        return Scan::Refused;
                    }
                    match udp_conntrack::parse_entry(&payload[4..], self.peer) {
                        Lookup::Absent => {}
                        Lookup::Refused => return Scan::Refused,
                        Lookup::Found(dst) => {
                            if self.found.is_some_and(|prior| prior != dst) {
                                return Scan::Refused;
                            }
                            self.found = Some(dst);
                        }
                    }
                }
                _ => return Scan::Refused,
            }
            offset += (length + 3) & !3;
            if offset > buffer.len() {
                // A final unpadded message has no remaining payload to scan.
                if offset - buffer.len() > 3 {
                    return Scan::Refused;
                }
                offset = buffer.len();
            }
        }
        if done {
            Scan::Complete(self.found.map(Lookup::Found).unwrap_or(Lookup::Absent))
        } else {
            Scan::More
        }
    }
}

fn u16_ne(bytes: &[u8]) -> u16 {
    u16::from_ne_bytes([bytes[0], bytes[1]])
}

fn u32_ne(bytes: &[u8]) -> u32 {
    u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
// SCANNER_ROLE_END

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::net::Ipv4Addr;

    fn peer() -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 1200)
    }

    fn dst(last: u8) -> SocketAddrV4 {
        SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, last), 443)
    }

    fn nla(kind: u16, payload: &[u8]) -> Vec<u8> {
        let length = payload.len() + 4;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(length as u16).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(payload);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn original(protocol: u8, destination: SocketAddrV4) -> Vec<u8> {
        let mut ip = nla(1, &peer().ip().octets());
        ip.extend(nla(2, &destination.ip().octets()));
        let mut proto = nla(1, &[protocol]);
        proto.extend(nla(2, &peer().port().to_be_bytes()));
        proto.extend(nla(3, &destination.port().to_be_bytes()));
        let mut tuple = nla(0x8001, &ip);
        tuple.extend(nla(0x8002, &proto));
        nla(0x8001, &tuple)
    }

    fn message(kind: u16, flags: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&((16 + payload.len()) as u32).to_ne_bytes());
        bytes.extend_from_slice(&kind.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&0u32.to_ne_bytes());
        bytes.extend_from_slice(payload);
        while bytes.len() % 4 != 0 {
            bytes.push(0);
        }
        bytes
    }

    fn entry(protocol: u8, destination: SocketAddrV4) -> Vec<u8> {
        let mut payload = vec![2, 0, 0, 0];
        payload.extend(original(protocol, destination));
        message(0x100, 2, 7, &payload)
    }

    fn done() -> Vec<u8> {
        message(3, 2, 7, &0u32.to_ne_bytes())
    }

    fn dump(chunks: Vec<Vec<u8>>, control: &Control<'_>) -> Lookup {
        let mut chunks: VecDeque<_> = chunks.into();
        lookup_dump(peer(), 7, control, |buffer, observed| {
            assert!(std::ptr::eq(observed, control));
            let Some(chunk) = chunks.pop_front() else {
                return Err(());
            };
            assert!(chunk.len() <= buffer.len());
            buffer[..chunk.len()].copy_from_slice(&chunk);
            Ok(Received {
                len: chunk.len(),
                kernel_peer: true,
                truncated: false,
            })
        })
    }

    #[test]
    fn fresh_datagram_owner_does_not_reuse_peer_destination() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let mut owner = Resolver::default();
        let now = Instant::now();
        let calls = Cell::new(0);
        assert_eq!(
            owner.resolve(
                SocketAddr::V4(peer()),
                now,
                &control,
                |actual_peer, observed| {
                    assert_eq!(actual_peer, peer());
                    assert!(std::ptr::eq(observed, &control));
                    calls.set(calls.get() + 1);
                    Some(dst(1))
                }
            ),
            Some(SocketAddr::V4(dst(1)))
        );
        assert_eq!(
            owner.resolve(SocketAddr::V4(peer()), now, &control, |_, _| {
                calls.set(calls.get() + 1);
                Some(dst(2))
            }),
            Some(SocketAddr::V4(dst(2)))
        );
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn prior_peer_destination_cannot_bypass_selected_stop() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let mut owner = Resolver::default();
        let now = Instant::now();
        assert_eq!(
            owner.resolve(SocketAddr::V4(peer()), now, &control, |_, _| Some(dst(1))),
            Some(SocketAddr::V4(dst(1)))
        );
        stop.store(true, Ordering::SeqCst);
        assert_eq!(
            owner.resolve(SocketAddr::V4(peer()), now, &control, |_, _| panic!(
                "stopped lookup invoked"
            )),
            None
        );
    }

    #[test]
    fn multipart_conflicting_destination_never_publishes_first_match() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        assert_eq!(
            dump(vec![entry(17, dst(1)), entry(17, dst(2)), done()], &control),
            Lookup::Refused
        );
    }

    #[test]
    fn matching_entry_without_dump_completion_is_refused() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        assert_eq!(dump(vec![entry(17, dst(1))], &control), Lookup::Refused);
    }

    #[test]
    fn wrong_sequence_cannot_publish_matching_entry() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let mut wrong = entry(17, dst(1));
        wrong[8..12].copy_from_slice(&8u32.to_ne_bytes());
        assert_eq!(dump(vec![wrong, done()], &control), Lookup::Refused);
    }

    #[test]
    fn interrupted_dump_cannot_publish_matching_entry() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let mut interrupted = entry(17, dst(1));
        interrupted[6..8].copy_from_slice(&(2u16 | 0x10).to_ne_bytes());
        assert_eq!(dump(vec![interrupted, done()], &control), Lookup::Refused);
    }

    #[test]
    fn complete_unique_udp_destination_retains_positive_result() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        assert_eq!(
            dump(vec![entry(17, dst(1)), entry(17, dst(1)), done()], &control),
            Lookup::Found(dst(1))
        );
    }

    #[test]
    fn unrelated_receives_keep_the_same_original_cutoff_and_owner() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let cutoff = control.deadline;
        let mut chunks: VecDeque<_> = vec![entry(6, dst(1)), entry(6, dst(2)), done()].into();
        let mut cutoffs = Vec::new();
        let result = lookup_dump(peer(), 7, &control, |buffer, observed| {
            assert!(std::ptr::eq(observed, &control));
            cutoffs.push(observed.deadline);
            let chunk = chunks.pop_front().expect("actual unrelated input");
            buffer[..chunk.len()].copy_from_slice(&chunk);
            Ok(Received {
                len: chunk.len(),
                kernel_peer: true,
                truncated: false,
            })
        });
        assert_eq!(result, Lookup::Absent);
        assert_eq!(cutoffs, vec![cutoff; 3]);
        assert_eq!(control.deadline, cutoff);
    }

    #[test]
    fn expired_original_cutoff_refuses_before_source_acquisition() {
        let stop = AtomicBool::new(false);
        let control = Control::expired(&stop);
        assert_eq!(
            resolve_sources(
                peer(),
                &control,
                || panic!("expired proc read"),
                |_| panic!("expired native read")
            ),
            None
        );
    }

    #[test]
    fn oversized_proc_snapshot_refuses_without_native_fallback() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let calls = Cell::new(0);
        let result = resolve_sources(
            peer(),
            &control,
            || ProcSnapshot::Complete(vec![b' '; MAX_LOOKUP_BYTES + 1]),
            |_| {
                calls.set(calls.get() + 1);
                Lookup::Found(dst(1))
            },
        );
        assert_eq!(result, None);
        assert_eq!(calls.get(), 0);
    }

    #[test]
    fn proc_known_ambiguity_retains_refusal_before_native_fallback() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let bytes = b"ipv4 2 udp 17 29 src=192.0.2.1 dst=198.51.100.1 sport=1200 dport=443\nipv4 2 udp 17 29 src=192.0.2.1 dst=198.51.100.2 sport=1200 dport=443\n".to_vec();
        assert_eq!(
            resolve_sources(
                peer(),
                &control,
                || ProcSnapshot::Complete(bytes),
                |_| panic!("ambiguous proc selected native fallback")
            ),
            None
        );
    }

    #[test]
    fn receive_stop_is_observed_before_result_publication() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let chunk = entry(17, dst(1));
        let result = lookup_dump(peer(), 7, &control, |buffer, _| {
            buffer[..chunk.len()].copy_from_slice(&chunk);
            stop.store(true, Ordering::SeqCst);
            Ok(Received {
                len: chunk.len(),
                kernel_peer: true,
                truncated: false,
            })
        });
        assert_eq!(result, Lookup::Refused);
    }

    #[test]
    fn native_peer_or_truncation_failure_refuses_before_parser() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let chunk = entry(17, dst(1));
        for (kernel_peer, truncated) in [(false, false), (true, true)] {
            let result = lookup_dump(peer(), 7, &control, |buffer, _| {
                buffer[..chunk.len()].copy_from_slice(&chunk);
                Ok(Received {
                    len: chunk.len(),
                    kernel_peer,
                    truncated,
                })
            });
            assert_eq!(result, Lookup::Refused);
        }
    }

    #[test]
    fn unavailable_proc_uses_the_same_selected_native_owner() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        let calls = Cell::new(0);
        assert_eq!(
            resolve_sources(
                peer(),
                &control,
                || ProcSnapshot::Unavailable,
                |actual_peer| {
                    assert_eq!(actual_peer, peer());
                    calls.set(calls.get() + 1);
                    Lookup::Found(dst(1))
                }
            ),
            Some(dst(1))
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn partial_proc_refusal_never_selects_native_fallback() {
        let stop = AtomicBool::new(false);
        let control = Control::new(&stop);
        assert_eq!(
            resolve_sources(
                peer(),
                &control,
                || ProcSnapshot::Refused,
                |_| panic!("partial proc selected native fallback")
            ),
            None
        );
    }
}
