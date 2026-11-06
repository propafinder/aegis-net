//! Owned bounded packet queues. Queueing is not delivery or relay health.
//!
//! A full queue is backpressure, never a session failure: the packet is
//! dropped and counted in that direction (`dropped_inbound` /
//! `dropped_outbound`) and the bridge stays open. Only an expired or
//! revoked lease, an owner stop or an invalid packet seals it.
#[cfg(feature = "client-engine")]
use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
use std::{
    collections::VecDeque,
    io,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};
const MAX_PACKET: usize = 65_535;
pub(crate) const MAX_PACKETS: usize = 128;
const MAX_BYTES: usize = 2 * 1024 * 1024;
#[derive(Default)]
struct Queue {
    frames: VecDeque<Vec<u8>>,
    bytes: usize,
}
impl Queue {
    fn put(&mut self, bytes: &[u8]) -> io::Result<()> {
        validate_packet(bytes)?;
        if self.frames.len() == MAX_PACKETS || self.bytes + bytes.len() > MAX_BYTES {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        self.frames.push_back(bytes.to_vec());
        self.bytes += bytes.len();
        Ok(())
    }
    fn take(&mut self) -> Option<Vec<u8>> {
        let b = self.frames.pop_front()?;
        self.bytes -= b.len();
        Some(b)
    }
}
fn is_full<T>(result: &io::Result<T>) -> bool {
    matches!(result, Err(error) if error.kind() == io::ErrorKind::WouldBlock)
}
pub fn validate_packet(p: &[u8]) -> io::Result<()> {
    if p.len() > MAX_PACKET {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let valid = match p.first().map(|b| b >> 4) {
        Some(4) if p.len() >= 20 => {
            let header = (p[0] & 15) as usize * 4;
            header >= 20
                && header <= p.len()
                && u16::from_be_bytes([p[2], p[3]]) as usize == p.len()
        }
        Some(6) if p.len() >= 40 => u16::from_be_bytes([p[4], p[5]]) as usize + 40 == p.len(),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(io::ErrorKind::InvalidData.into())
    }
}
/// Packets dropped on a full queue, per direction.
#[derive(Default)]
struct Dropped {
    inbound: AtomicU64,
    outbound: AtomicU64,
}

/// A drop is logged at the 1st, 2nd, 4th, 8th ... drop of its direction:
/// a sustained overflow logs O(log n) lines, never one per packet.
pub(crate) fn drop_logged(count: u64) -> bool {
    count.is_power_of_two()
}

fn record_drop(counter: &AtomicU64, direction: &'static str) {
    let count = counter.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if drop_logged(count) {
        log_drop(direction, count);
    }
}

/// The drop counter as a stable log field.
#[cfg_attr(not(all(target_os = "macos", feature = "apple")), allow(dead_code))]
fn drop_count_field(count: u64) -> String {
    format!("dropped:{count}")
}

#[cfg(all(target_os = "macos", feature = "apple"))]
fn log_drop(direction: &'static str, count: u64) {
    crate::apple::log_fields(DROP_EVENT, &[direction, &drop_count_field(count)]);
}
#[cfg(all(target_os = "macos", feature = "apple"))]
const DROP_EVENT: &str = "packet_queue_full_drop";
#[cfg(not(all(target_os = "macos", feature = "apple")))]
fn log_drop(_direction: &'static str, _count: u64) {}

#[derive(Clone)]
pub struct PacketBridge {
    input: Arc<Mutex<Queue>>,
    output: Arc<Mutex<Queue>>,
    stopped: Arc<AtomicBool>,
    dropped: Arc<Dropped>,
}
impl Default for PacketBridge {
    fn default() -> Self {
        Self {
            input: Default::default(),
            output: Default::default(),
            stopped: Arc::new(AtomicBool::new(false)),
            dropped: Default::default(),
        }
    }
}
impl PacketBridge {
    fn active(&self) -> io::Result<()> {
        if self.stopped.load(Ordering::Acquire) {
            Err(io::ErrorKind::NotConnected.into())
        } else {
            Ok(())
        }
    }
    fn put(&self, q: &Mutex<Queue>, p: &[u8]) -> io::Result<()> {
        let mut q = q.lock().map_err(|_| io::ErrorKind::Other)?;
        self.active()?;
        q.put(p)
    }
    fn take(&self, q: &Mutex<Queue>) -> io::Result<Option<Vec<u8>>> {
        let mut q = q.lock().map_err(|_| io::ErrorKind::Other)?;
        self.active()?;
        Ok(q.take())
    }
    /// A full input queue is `WouldBlock`: the packet is dropped and
    /// counted, the bridge stays open.
    pub fn from_os(&self, p: &[u8]) -> io::Result<()> {
        let result = self.put(&self.input, p);
        if is_full(&result) {
            record_drop(&self.dropped.inbound, "inbound");
        }
        result
    }
    pub fn engine_receive(&self) -> io::Result<Option<Vec<u8>>> {
        self.take(&self.input)
    }
    /// A full output queue is `WouldBlock`, which the engine drops and
    /// counts; the bridge stays open. Any other failure (a stopped bridge,
    /// an invalid packet) seals it.
    pub fn engine_send(&self, p: &[u8]) -> io::Result<()> {
        match self.put(&self.output, p) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                record_drop(&self.dropped.outbound, "outbound");
                Err(error)
            }
            Err(_) => {
                self.stop();
                Err(io::ErrorKind::NotConnected.into())
            }
        }
    }
    /// Packets dropped so far on a full input queue.
    pub fn dropped_inbound(&self) -> u64 {
        self.dropped.inbound.load(Ordering::Relaxed)
    }
    /// Packets dropped so far on a full output queue.
    pub fn dropped_outbound(&self) -> u64 {
        self.dropped.outbound.load(Ordering::Relaxed)
    }
    pub fn to_os(&self) -> io::Result<Option<Vec<u8>>> {
        self.take(&self.output)
    }
    pub fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        for q in [&self.input, &self.output] {
            if let Ok(mut q) = q.lock() {
                q.frames.clear();
                q.bytes = 0;
            }
        }
    }
}

/// The bridge lease end in bridge-clock (CLOCK_MONOTONIC_RAW) nanoseconds,
/// readable without a lock by relay-side owners. Zero is "no lease"; the
/// revoked bit is sticky, so a sealed bridge's deadline never reappears. Only
/// `LeasedPacketBridge::grant_until`, which owns an authenticated ACK, writes
/// a deadline here; readers judge expiry against the same bridge clock.
#[cfg(feature = "client-engine")]
#[derive(Clone, Default)]
pub(crate) struct RefreshableDeadline(Arc<AtomicU64>);

#[cfg(feature = "client-engine")]
const DEADLINE_REVOKED: u64 = 1 << 63;

#[cfg(feature = "client-engine")]
impl RefreshableDeadline {
    /// The current lease end, if one was granted and never revoked.
    // Relay-side owners (S06) gate relay work on these; tests use them now.
    #[allow(dead_code)]
    pub(crate) fn current(&self) -> Option<u64> {
        match self.0.load(Ordering::Acquire) {
            0 => None,
            value if value & DEADLINE_REVOKED != 0 => None,
            value => Some(value),
        }
    }

    /// True only strictly before an unrevoked deadline.
    #[allow(dead_code)]
    pub(crate) fn active_at(&self, now_ns: u64) -> bool {
        self.current().is_some_and(|until| now_ns < until)
    }

    /// The last granted lease end, revoked or not. Revocation withdraws
    /// authority but does not move time: this tells *why* a sealed bridge
    /// stopped, and never grants anything.
    pub(crate) fn last_granted(&self) -> Option<u64> {
        match self.0.load(Ordering::Acquire) & !DEADLINE_REVOKED {
            0 => None,
            value => Some(value),
        }
    }

    // Relay-side owners (S06) distinguish a revoked lease from none yet.
    #[allow(dead_code)]
    pub(crate) fn is_revoked(&self) -> bool {
        self.0.load(Ordering::Acquire) & DEADLINE_REVOKED != 0
    }

    fn refresh(&self, deadline_ns: u64) -> io::Result<()> {
        if deadline_ns == 0 || deadline_ns & DEADLINE_REVOKED != 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.0
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                (value & DEADLINE_REVOKED == 0).then_some(deadline_ns)
            })
            .map(|_| ())
            .map_err(|_| io::ErrorKind::NotConnected.into())
    }

    fn revoke(&self) {
        self.0.fetch_or(DEADLINE_REVOKED, Ordering::AcqRel);
    }
}

/// PacketFlow and engine share this gate over the *same* raw queues. A real
/// session owner must supply deadlines from authenticated ACKs and revoke on
/// cancellation; constructing this adapter alone grants no capture authority.
#[cfg(feature = "client-engine")]
#[derive(Clone)]
pub struct LeasedPacketBridge {
    raw: PacketBridge,
    deadline: CaptureLeaseDeadline,
    refreshable: RefreshableDeadline,
    clock: Arc<dyn Fn() -> io::Result<u64> + Send + Sync>,
}

#[cfg(feature = "client-engine")]
impl LeasedPacketBridge {
    pub fn new(raw: PacketBridge, deadline: CaptureLeaseDeadline) -> Self {
        Self {
            raw,
            deadline,
            refreshable: RefreshableDeadline::default(),
            clock: Arc::new(monotonic_ns),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_clock(
        raw: PacketBridge,
        deadline: CaptureLeaseDeadline,
        clock: impl Fn() -> io::Result<u64> + Send + Sync + 'static,
    ) -> Self {
        Self {
            raw,
            deadline,
            refreshable: RefreshableDeadline::default(),
            clock: Arc::new(clock),
        }
    }

    pub(crate) fn raw_clone(&self) -> PacketBridge {
        self.raw.clone()
    }

    fn use_queue<T>(
        &self,
        operation: impl FnOnce(&PacketBridge) -> io::Result<T>,
    ) -> io::Result<T> {
        self.raw.active()?;
        let result = self.deadline.while_active(
            || (self.clock)(),
            || {
                self.raw.stop();
                self.refreshable.revoke();
            },
            || operation(&self.raw),
        )?;
        if self.raw.active().is_err() {
            // The operation itself sealed the queues (an invalid packet).
            self.refreshable.revoke();
        }
        result
    }

    /// Polling this gate also seals queues on an expired or revoked lease
    /// while packetFlow is idle. The owner retains and joins the polling task.
    pub(crate) fn probe_lease(&self) -> io::Result<()> {
        self.use_queue(|_| Ok(()))
    }

    pub(crate) fn is_sealed(&self) -> bool {
        self.raw.active().is_err()
    }

    /// S16o: the frames queued for packetFlow output (a full queue drops and
    /// counts further packets); `MAX_PACKETS` when it cannot be read.
    pub(crate) fn output_len(&self) -> usize {
        self.raw
            .output
            .lock()
            .map_or(MAX_PACKETS, |queue| queue.frames.len())
    }

    /// The exact clock this gate enforces deadlines against. The session body
    /// reads it before the ACK request so a derived lease never outlives it.
    pub(crate) fn clock_ns(&self) -> io::Result<u64> {
        (self.clock)()
    }

    /// Install an ACK-derived deadline on this gate's clock. The caller owns
    /// the authenticated ACK; a sealed bridge is never reopened by a grant.
    pub(crate) fn grant_until(&self, deadline_ns: u64) -> io::Result<()> {
        self.raw.active()?;
        self.deadline.replace(Some(deadline_ns))?;
        let refreshed = self.refreshable.refresh(deadline_ns);
        if refreshed.is_err() || self.raw.active().is_err() {
            // A concurrent stop sealed the queues after the first check.
            let _ = self.deadline.replace(None);
            self.refreshable.revoke();
            return Err(io::ErrorKind::NotConnected.into());
        }
        Ok(())
    }

    /// True once the bridge clock has reached the last granted lease end, when
    /// the clock cannot be read, or when nothing was ever granted. A bridge
    /// sealed mid-lease (engine exit, an invalid outbound packet, owner stop)
    /// has not elapsed: classify only, never authorize, from this. A full
    /// output queue is backpressure (`WouldBlock`, counted as an outbound
    /// drop) and never seals.
    pub(crate) fn lease_elapsed(&self) -> bool {
        match (self.clock_ns(), self.refreshable.last_granted()) {
            (Ok(now), Some(until)) => now >= until,
            _ => true,
        }
    }

    /// The lock-free view of this gate's lease end, shared with relay-side
    /// owners. It is revoked, permanently, by `stop`.
    // Handed to relay-side owners in S06; observed only by tests until then.
    #[allow(dead_code)]
    pub(crate) fn refreshable_deadline(&self) -> RefreshableDeadline {
        self.refreshable.clone()
    }

    pub fn from_os(&self, packet: &[u8]) -> io::Result<()> {
        self.use_queue(|raw| raw.from_os(packet))
    }
    /// B-06 S16j-2: one packet read from packetFlow. A tunnel-local
    /// destination the engine does not serve (`policy::native_packet_admitted`)
    /// is dropped, `Ok(false)`, before the lease or the queue is touched;
    /// every other packet goes to `from_os` exactly as before, `Ok(true)`.
    /// A full input queue drops (and counts) the packet under a valid
    /// lease, `Ok(false)`: backpressure, never a session failure. Lease
    /// expiry, revocation and a stopped bridge still fail.
    pub fn from_native(&self, packet: &[u8]) -> io::Result<bool> {
        if !crate::policy::native_packet_admitted(packet) {
            return Ok(false);
        }
        match self.from_os(packet) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(error) => Err(error),
        }
    }
    /// Packets dropped so far on a full input queue.
    pub fn dropped_inbound(&self) -> u64 {
        self.raw.dropped_inbound()
    }
    /// Packets dropped so far on a full output queue.
    pub fn dropped_outbound(&self) -> u64 {
        self.raw.dropped_outbound()
    }
    pub fn engine_receive(&self) -> io::Result<Option<Vec<u8>>> {
        self.use_queue(PacketBridge::engine_receive)
    }
    pub fn engine_send(&self, packet: &[u8]) -> io::Result<()> {
        self.use_queue(|raw| raw.engine_send(packet))
    }
    /// Hold the lease until the native write has returned. Revocation cannot
    /// complete between dequeue and delivery to packetFlow.
    pub fn deliver_to_os(&self, write: impl FnOnce(&[u8]) -> io::Result<()>) -> io::Result<bool> {
        self.use_queue(|raw| match raw.to_os()? {
            Some(packet) => {
                write(&packet)?;
                Ok(true)
            }
            None => Ok(false),
        })
    }

    #[cfg(test)]
    pub fn to_os(&self) -> io::Result<Option<Vec<u8>>> {
        self.use_queue(PacketBridge::to_os)
    }
    pub fn stop(&self) {
        // This is the composite owner's cancellation/revocation operation.
        // Seal both queues immediately, then wait for any in-flight native
        // write before publishing the revoked deadline.
        self.raw.stop();
        self.refreshable.revoke();
        let _ = self.deadline.replace(None);
    }
}

/// Seal the exact packet bridge before a containing online owner releases its
/// authenticated channel or protected Store. This guard grants no lease.
#[cfg(feature = "client-engine")]
pub(crate) struct RevokeLeaseOnDrop {
    bridge: LeasedPacketBridge,
}

#[cfg(feature = "client-engine")]
impl RevokeLeaseOnDrop {
    pub(crate) fn new(bridge: LeasedPacketBridge) -> Self {
        Self { bridge }
    }
}

#[cfg(feature = "client-engine")]
impl Drop for RevokeLeaseOnDrop {
    fn drop(&mut self) {
        self.bridge.stop();
    }
}

// Production deadlines use the same kernel-wide epoch as the protected
// worker control channel, so no process-relative timestamp crosses owners.
#[cfg(all(feature = "client-engine", target_os = "macos", feature = "apple"))]
fn monotonic_ns() -> io::Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(value.tv_nsec as u64))
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

#[cfg(all(
    feature = "client-engine",
    not(all(target_os = "macos", feature = "apple"))
))]
fn monotonic_ns() -> io::Result<u64> {
    use std::{sync::OnceLock, time::Instant};
    static START: OnceLock<Instant> = OnceLock::new();
    u64::try_from(START.get_or_init(Instant::now).elapsed().as_nanos())
        .map_err(|_| io::ErrorKind::InvalidData.into())
}
// Concrete implementation must retain its worker and credential/renewal owner.
// No public boolean or providerConfiguration string can manufacture this lease.
pub trait EngineOwner: Send {
    fn constructed(&self) -> bool;
    fn stop_and_observe_terminal(&mut self) -> io::Result<()>;
    fn terminal(&self) -> bool;
}
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(feature = "client-engine")]
    use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
    #[cfg(feature = "client-engine")]
    use std::sync::atomic::AtomicU64;
    #[cfg(feature = "client-engine")]
    use std::sync::mpsc;
    fn frame() -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p
    }
    #[test]
    fn stop_discards_queued_packets_and_rejects_late_callbacks() {
        let q = PacketBridge::default();
        q.from_os(&frame()).unwrap();
        q.engine_send(&frame()).unwrap();
        q.stop();
        assert!(q.engine_receive().is_err());
        assert!(q.to_os().is_err());
        assert!(q.from_os(&frame()).is_err());
    }
    #[test]
    fn outbound_saturation_drops_and_counts_without_sealing() {
        let q = PacketBridge::default();
        for _ in 0..MAX_PACKETS {
            q.engine_send(&frame()).unwrap();
        }
        for dropped in 1..=3 {
            assert_eq!(
                q.engine_send(&frame()).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            assert_eq!(q.dropped_outbound(), dropped);
        }
        assert_eq!(q.dropped_inbound(), 0);
        // Still open in both directions: the queued packets drain, and a
        // drained slot is reused.
        assert_eq!(q.output.lock().unwrap().frames.len(), MAX_PACKETS);
        assert_eq!(q.to_os().unwrap(), Some(frame()));
        q.engine_send(&frame()).unwrap();
        q.from_os(&frame()).unwrap();
        assert_eq!(q.engine_receive().unwrap(), Some(frame()));
        // An invalid packet still seals.
        assert_eq!(
            q.engine_send(&[0x45]).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(q.to_os().is_err());
        assert!(q.from_os(&frame()).is_err());
    }
    #[test]
    fn full_input_refuses_without_unbounded_growth() {
        let q = PacketBridge::default();
        for _ in 0..MAX_PACKETS {
            q.from_os(&frame()).unwrap();
        }
        assert_eq!(
            q.from_os(&frame()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(q.input.lock().unwrap().frames.len(), MAX_PACKETS);
        assert_eq!(q.dropped_inbound(), 1);
        assert_eq!(q.dropped_outbound(), 0);
        assert_eq!(q.engine_receive().unwrap(), Some(frame()));
        q.from_os(&frame()).unwrap();
    }
    #[test]
    fn full_queue_drops_are_logged_at_powers_of_two_only() {
        let logged: Vec<u64> = (1..=1024).filter(|n| drop_logged(*n)).collect();
        assert_eq!(logged, [1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024]);
        assert!(!drop_logged(0));
        assert!(!drop_logged(3));
        assert_eq!(drop_count_field(128), "dropped:128");
        #[cfg(all(target_os = "macos", feature = "apple"))]
        for direction in ["inbound", "outbound"] {
            assert!(crate::apple::stable_fields(
                DROP_EVENT,
                &[direction, &drop_count_field(u64::MAX)]
            ));
        }
    }

    #[cfg(feature = "client-engine")]
    fn leased(now: Arc<AtomicU64>, deadline: CaptureLeaseDeadline) -> LeasedPacketBridge {
        LeasedPacketBridge::with_clock(PacketBridge::default(), deadline, move || {
            Ok(now.load(Ordering::SeqCst))
        })
    }

    #[cfg(feature = "client-engine")]
    #[test]
    fn no_ack_seals_every_packet_direction_and_later_deadline_cannot_reopen() {
        let now = Arc::new(AtomicU64::new(10));
        for direction in 0..4 {
            let deadline = CaptureLeaseDeadline::default();
            let bridge = leased(now.clone(), deadline.clone());
            let failure = match direction {
                0 => bridge.from_os(&frame()),
                1 => bridge.engine_receive().map(|_| ()),
                2 => bridge.engine_send(&frame()),
                _ => bridge.to_os().map(|_| ()),
            };
            assert_eq!(failure.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
            deadline.replace(Some(20)).unwrap();
            assert_eq!(
                bridge.from_os(&frame()).unwrap_err().kind(),
                io::ErrorKind::NotConnected
            );
            assert_eq!(
                bridge.engine_receive().unwrap_err().kind(),
                io::ErrorKind::NotConnected
            );
            assert_eq!(
                bridge.engine_send(&frame()).unwrap_err().kind(),
                io::ErrorKind::NotConnected
            );
            assert_eq!(
                bridge.to_os().unwrap_err().kind(),
                io::ErrorKind::NotConnected
            );
        }
    }

    #[cfg(feature = "client-engine")]
    #[test]
    fn refreshable_deadline_follows_grants_and_revocation_is_permanent() {
        let now = Arc::new(AtomicU64::new(10));
        let bridge = leased(now, CaptureLeaseDeadline::default());
        let shared = bridge.refreshable_deadline();
        assert_eq!(shared.current(), None);
        assert!(!shared.active_at(0));
        bridge.grant_until(50).unwrap();
        assert_eq!(shared.current(), Some(50));
        assert!(shared.active_at(49));
        assert!(!shared.active_at(50));
        // A later authenticated grant replaces, and may shorten, the lease.
        bridge.grant_until(40).unwrap();
        assert_eq!(shared.current(), Some(40));
        for invalid in [0, DEADLINE_REVOKED, u64::MAX] {
            assert_eq!(
                shared.refresh(invalid).unwrap_err().kind(),
                io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(shared.current(), Some(40));
        bridge.stop();
        assert!(shared.is_revoked());
        assert_eq!(shared.current(), None);
        // An expired lease seen on the packet path revokes the view too, and
        // so does the engine sealing the queues with an invalid packet.
        // Outbound saturation is backpressure: it revokes nothing.
        let now = Arc::new(AtomicU64::new(10));
        let expired = leased(now.clone(), CaptureLeaseDeadline::default());
        expired.grant_until(20).unwrap();
        now.store(20, Ordering::SeqCst);
        assert!(expired.from_os(&frame()).is_err());
        assert!(expired.refreshable_deadline().is_revoked());
        now.store(10, Ordering::SeqCst);
        let saturated = leased(now, CaptureLeaseDeadline::default());
        saturated.grant_until(20).unwrap();
        while saturated.engine_send(&frame()).is_ok() {}
        assert_eq!(saturated.dropped_outbound(), 1);
        assert_eq!(saturated.refreshable_deadline().current(), Some(20));
        assert!(saturated.engine_send(&[0x45]).is_err());
        assert!(saturated.refreshable_deadline().is_revoked());
        assert_eq!(shared.current(), None);
        assert!(!shared.active_at(0));
        // Neither a direct refresh nor a bridge grant revives a revoked view.
        assert_eq!(
            shared.refresh(100).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        assert!(bridge.grant_until(100).is_err());
        assert_eq!(shared.current(), None);
        assert!(shared.is_revoked());
    }

    #[cfg(feature = "client-engine")]
    #[test]
    fn lease_elapsed_is_judged_on_time_and_revocation_grants_nothing() {
        // Never granted, or an unreadable clock: elapsed.
        let now = Arc::new(AtomicU64::new(10));
        let bridge = leased(now.clone(), CaptureLeaseDeadline::default());
        assert_eq!(bridge.refreshable_deadline().last_granted(), None);
        assert!(bridge.lease_elapsed());
        let broken = LeasedPacketBridge::with_clock(
            PacketBridge::default(),
            CaptureLeaseDeadline::default(),
            || Err(io::Error::other("clock unavailable")),
        );
        assert!(broken.lease_elapsed());
        // Revoked before any grant: still nothing granted.
        broken.stop();
        assert_eq!(broken.refreshable_deadline().last_granted(), None);

        bridge.grant_until(50).unwrap();
        assert!(!bridge.lease_elapsed());
        // An owner stop mid-lease revokes authority but is not an expiry.
        bridge.stop();
        let shared = bridge.refreshable_deadline();
        assert_eq!(shared.last_granted(), Some(50));
        assert!(!bridge.lease_elapsed());
        // The remembered end never re-opens the gate or the view.
        assert_eq!(shared.current(), None);
        assert!(!shared.active_at(10));
        assert!(bridge.from_os(&frame()).is_err());
        assert!(bridge.probe_lease().is_err());
        assert!(bridge.grant_until(60).is_err());
        assert_eq!(shared.last_granted(), Some(50));
        now.store(49, Ordering::SeqCst);
        assert!(!bridge.lease_elapsed());
        now.store(50, Ordering::SeqCst);
        assert!(bridge.lease_elapsed());

        // An invalid outbound packet mid-lease: sealed and revoked, not
        // elapsed.
        let now = Arc::new(AtomicU64::new(10));
        let saturated = leased(now, CaptureLeaseDeadline::default());
        saturated.grant_until(20).unwrap();
        while saturated.engine_send(&frame()).is_ok() {}
        assert!(!saturated.is_sealed());
        assert!(saturated.engine_send(&[0x45]).is_err());
        assert!(saturated.refreshable_deadline().is_revoked());
        assert_eq!(saturated.refreshable_deadline().last_granted(), Some(20));
        assert!(!saturated.lease_elapsed());
    }

    #[cfg(feature = "client-engine")]
    #[test]
    fn leased_full_queues_drop_and_count_while_the_lease_holds() {
        let now = Arc::new(AtomicU64::new(10));
        let deadline = CaptureLeaseDeadline::default();
        let bridge = leased(now.clone(), deadline);
        bridge.grant_until(50).unwrap();
        // Inbound: a burst past the bound is dropped, `Ok(false)`, counted.
        let mut admitted = 0;
        for _ in 0..MAX_PACKETS + 40 {
            if bridge.from_native(&frame()).unwrap() {
                admitted += 1;
            }
        }
        assert_eq!(admitted, MAX_PACKETS);
        assert_eq!(bridge.dropped_inbound(), 40);
        // Outbound: WouldBlock, which the engine drops and counts.
        for _ in 0..MAX_PACKETS {
            bridge.engine_send(&frame()).unwrap();
        }
        for _ in 0..25 {
            assert_eq!(
                bridge.engine_send(&frame()).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        assert_eq!(bridge.dropped_outbound(), 25);
        // Nothing sealed or revoked: both directions still flow.
        assert!(!bridge.is_sealed());
        assert_eq!(bridge.refreshable_deadline().current(), Some(50));
        assert!(bridge.probe_lease().is_ok());
        assert!(bridge.deliver_to_os(|_| Ok(())).unwrap());
        assert_eq!(bridge.engine_receive().unwrap(), Some(frame()));
        assert!(bridge.from_native(&frame()).unwrap());
        // Lease expiry still seals, full queue or not.
        now.store(50, Ordering::SeqCst);
        assert_eq!(
            bridge.from_native(&frame()).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(bridge.is_sealed());
        assert!(bridge.refreshable_deadline().is_revoked());
        assert_eq!(
            bridge.from_native(&frame()).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[cfg(feature = "client-engine")]
    #[test]
    fn authenticated_deadline_allows_queues_then_owner_stop_discards_both() {
        let now = Arc::new(AtomicU64::new(10));
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let bridge = leased(now, deadline.clone());
        bridge.from_os(&frame()).unwrap();
        bridge.engine_send(&frame()).unwrap();
        assert_eq!(bridge.raw.input.lock().unwrap().frames.len(), 1);
        assert_eq!(bridge.raw.output.lock().unwrap().frames.len(), 1);
        bridge.stop();
        assert!(bridge.raw.input.lock().unwrap().frames.is_empty());
        assert!(bridge.raw.output.lock().unwrap().frames.is_empty());
        assert_eq!(
            bridge.to_os().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        deadline.replace(Some(30)).unwrap();
        assert_eq!(
            bridge.from_os(&frame()).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[cfg(feature = "client-engine")]
    #[test]
    fn expiry_and_clock_failure_seal_before_queued_packet_delivery() {
        let now = Arc::new(AtomicU64::new(10));
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let bridge = leased(now.clone(), deadline);
        bridge.engine_send(&frame()).unwrap();
        now.store(20, Ordering::SeqCst);
        assert_eq!(
            bridge.to_os().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert!(bridge.raw.output.lock().unwrap().frames.is_empty());

        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let broken = LeasedPacketBridge::with_clock(PacketBridge::default(), deadline, || {
            Err(io::Error::other("clock unavailable"))
        });
        assert_eq!(
            broken.from_os(&frame()).unwrap_err().kind(),
            io::ErrorKind::Other
        );
        assert_eq!(
            broken.to_os().unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
    }

    #[cfg(feature = "client-engine")]
    #[test]
    fn revocation_waits_for_native_delivery_and_next_packet_is_denied() {
        let now = Arc::new(AtomicU64::new(10));
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let bridge = leased(now, deadline.clone());
        bridge.engine_send(&frame()).unwrap();
        bridge.engine_send(&frame()).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let delivering = bridge.clone();
        let writer = std::thread::spawn(move || {
            delivering
                .deliver_to_os(|packet| {
                    assert_eq!(packet, frame());
                    entered_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    Ok(())
                })
                .unwrap()
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        let (revoked_tx, revoked_rx) = mpsc::channel();
        let revoking = bridge.clone();
        let revoker = std::thread::spawn(move || {
            revoking.stop();
            revoked_tx.send(()).unwrap();
        });
        assert!(revoked_rx.try_recv().is_err());
        release_tx.send(()).unwrap();
        assert!(writer.join().unwrap());
        revoked_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        revoker.join().unwrap();
        assert!(bridge.raw.output.lock().unwrap().frames.is_empty());
        assert_eq!(
            bridge
                .deliver_to_os(|_| panic!("late packet delivered"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotConnected
        );
    }
}
