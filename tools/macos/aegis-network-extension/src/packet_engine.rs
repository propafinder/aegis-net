//! Opt-in actual shared packet engine mechanics. This is not a provider factory,
//! device/PKI/ACK permit, native packetFlow admission or composite session owner.
use crate::{bridge::LeasedPacketBridge, engine::ThreadEngine};
use aegis_client::{
    packet_engine::{
        run_ready_with_services,
        services::{EngineEvent, EventSink, RelayServices, RelayWork},
    },
    relay_runtime_types::{ConnectTarget, UdpPacket},
    PacketIo, TunnelStats,
};
use aegis_core::RelaySettings;
use std::{
    collections::VecDeque,
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tokio::{net::TcpStream, sync::mpsc};
const MAX_RELAY_WORK: usize = 4096;
const LEASE_WATCH_INTERVAL: Duration = Duration::from_millis(10);
const MAX_JOIN_BUDGET: Duration = Duration::from_secs(2);
/// B-06 S20c: SYNs of one destination port the device hands the shared
/// engine between two of its polls. The engine (aegis-client
/// packet_engine/engine.rs, `LISTENERS_PER_PORT`) keeps four listening
/// sockets per destination port and tops them up only after its poll; a SYN
/// that poll finds no listener for is answered with a RST before any relay
/// work. Installed v24 (r15) lost 5 of 24 and 12 of 90 burst flows that way
/// (the bursts ended in 1.66 s and 4.23 s of curl's 10 s) with no flow
/// refusal of the session logged at all; r13's 24-flow burst lost 8 so.
pub(crate) const SYNS_PER_PORT_PER_POLL: usize = 4;
/// The packets the shared engine reads before it polls, at most
/// (`run_ready_with_services`: 256 per loop, or fewer when the device has
/// none): the device's batch ends there even when no read came back empty.
pub(crate) const ENGINE_BATCH: usize = 256;
/// S16o: the SYNs a device holds back for later batches at most. Past it a
/// SYN is dropped, and the app retransmits it.
pub(crate) const MAX_HELD_SYNS: usize = 256;
/// Shared library contract over the existing bounded native queues. No routing,
/// transport, certificate or permit semantics are copied into this device.
pub struct NePacketDevice {
    bridge: LeasedPacketBridge,
    stop: Arc<AtomicBool>,
    pace: SynPace,
    /// S16o: the TCP flows this device's engine answered, handed to the
    /// epoch's ledger when the device ends.
    flows: flows::Flows,
    ledger: flows::FlowLedger,
    /// S20g: the flows this device's engine answered, by port class.
    opens: flows::OpenLog,
}
/// S20c: the SYNs per destination port of the engine's current batch, and
/// the SYNs held back for its later batches (an empty read, or
/// `ENGINE_BATCH` reads, end a batch, so the engine polls, promotes and tops
/// up its listeners before the next one). S16o: holding a SYN never ends
/// the batch: every other packet behind it still joins, so the bridge input
/// (128 frames, whose overflow ends the session) drains at the engine's full
/// rate while a SYN burst is paced. A held SYN's connection has no later
/// packet yet (the app waits for its SYN-ACK); held SYNs keep their order.
#[derive(Default)]
struct SynPace {
    held: VecDeque<(u16, Vec<u8>)>,
    ports: Vec<(u16, usize)>,
    delivered: usize,
    dropped: usize,
}
impl SynPace {
    fn room(&self, port: u16) -> bool {
        self.ports
            .iter()
            .find(|(seen, _)| *seen == port)
            .is_none_or(|(_, count)| *count < SYNS_PER_PORT_PER_POLL)
    }
    fn count(&mut self, port: u16) {
        match self.ports.iter_mut().find(|(seen, _)| *seen == port) {
            Some((_, count)) => *count += 1,
            None => self.ports.push((port, 1)),
        }
    }
    /// The oldest held SYN whose port has room in this batch, counted.
    fn release(&mut self) -> Option<Vec<u8>> {
        let index = self.held.iter().position(|(port, _)| self.room(*port))?;
        let (port, packet) = self.held.remove(index)?;
        self.count(port);
        Some(packet)
    }
    /// Whether `packet`, read from the bridge, joins this batch: anything
    /// but a SYN does, a SYN while its port has had fewer than
    /// `SYNS_PER_PORT_PER_POLL`; any other SYN is held (or dropped).
    fn admit(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
        if let Some(port) = tcp_syn_port(&packet) {
            if !self.room(port) {
                if self.held.len() < MAX_HELD_SYNS {
                    self.held.push_back((port, packet));
                } else {
                    self.dropped += 1;
                }
                return None;
            }
            self.count(port);
        }
        Some(packet)
    }
    /// A packet joined the batch.
    fn delivered(&mut self) {
        self.delivered += 1;
        if self.delivered >= ENGINE_BATCH {
            self.end_batch();
        }
    }
    fn batch_start(&self) -> bool {
        self.delivered == 0 && self.ports.is_empty()
    }
    /// The engine polls next.
    fn end_batch(&mut self) {
        self.ports.clear();
        self.delivered = 0;
    }
}
/// The destination port of an IPv4 or IPv6 TCP segment that opens a
/// connection (SYN, no ACK, no RST). IPv4 fragments past the first and IPv6
/// packets with extension headers are not counted (the engine reassembles
/// or drops them as before).
fn tcp_syn_port(packet: &[u8]) -> Option<u16> {
    flows::segment(packet)
        .filter(flows::Segment::opens)
        .map(|segment| segment.dport)
}
// Private error provenance travels with the actual refused operation. A later
// stop request cannot turn an unrelated bridge error into this cause witness.
#[derive(Debug)]
struct CancelRefusal;
impl std::fmt::Display for CancelRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("owned packet device observed cancellation")
    }
}
impl std::error::Error for CancelRefusal {}
fn is_cancel_refusal(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotConnected
        && error
            .get_ref()
            .is_some_and(|cause| cause.is::<CancelRefusal>())
}
impl NePacketDevice {
    pub fn new(bridge: LeasedPacketBridge, stop: Arc<AtomicBool>) -> Self {
        Self::on_ledger(bridge, stop, flows::FlowLedger::default())
    }
    /// S16o: a device whose answered flows go to `ledger` when it ends, and
    /// that resets the ledger's orphans of the epoch's earlier sessions.
    pub(crate) fn on_ledger(
        bridge: LeasedPacketBridge,
        stop: Arc<AtomicBool>,
        ledger: flows::FlowLedger,
    ) -> Self {
        Self {
            bridge,
            stop,
            pace: SynPace::default(),
            flows: flows::Flows::default(),
            ledger,
            opens: flows::OpenLog::default(),
        }
    }
    fn active(&self) -> io::Result<()> {
        if self.stop.load(Ordering::Acquire) {
            self.bridge.stop();
            Err(io::Error::new(io::ErrorKind::NotConnected, CancelRefusal))
        } else {
            Ok(())
        }
    }
    fn deliver(&mut self, packet: Vec<u8>) -> Option<Vec<u8>> {
        if let Some(segment) = flows::segment(&packet) {
            self.flows.app_sent(&segment);
        }
        self.pace.delivered();
        Some(packet)
    }
    /// S16o: reset a few of the epoch's orphaned flows towards the app,
    /// while this bridge's output has room.
    fn reset_orphans(&mut self) -> io::Result<()> {
        if self.ledger.pending() == 0 || self.bridge.output_len() >= flows::RESET_OUTPUT_ROOM {
            return Ok(());
        }
        let own = &self.flows;
        let orphans = self
            .ledger
            .take(flows::RESETS_PER_BATCH, |key| own.contains(key));
        let sent = send_resets(&self.bridge, &orphans)?;
        if sent > 0 {
            self.ledger.note_reset(sent);
            flows::log_resets(sent, self.ledger.pending());
        }
        Ok(())
    }
}
/// S16o and the audit backpressure: write `orphans`' resets to the app and
/// return how many went out. A reset that meets a full output queue is
/// dropped and counted (`dropped_outbound`) like any engine packet: it
/// neither seals the bridge nor fails the engine's `receive`. Only a sealed,
/// stopped or expired bridge (or an invalid reset) is an error.
fn send_resets(bridge: &LeasedPacketBridge, orphans: &[flows::Orphan]) -> io::Result<usize> {
    let mut sent = 0;
    for reset in orphans.iter().filter_map(flows::Orphan::reset) {
        match bridge.engine_send(&reset) {
            Ok(()) => sent += 1,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(sent)
}
impl PacketIo for NePacketDevice {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.active()?;
        if self.pace.batch_start() {
            self.reset_orphans()?;
        }
        if let Some(packet) = self.pace.release() {
            return Ok(self.deliver(packet));
        }
        loop {
            let Some(packet) = self.bridge.engine_receive()? else {
                self.pace.end_batch();
                return Ok(None);
            };
            // S20c: a held SYN waits for a later batch, after its port's
            // listeners are topped up; the packets behind it go on.
            if let Some(packet) = self.pace.admit(packet) {
                return Ok(self.deliver(packet));
            }
        }
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.active()?;
        self.bridge.engine_send(packet)?;
        if let Some(segment) = flows::segment(packet) {
            // S20g: the engine's first SYN-ACK of a flow, by the class of
            // the port the app connected to (the segment's source).
            if self.flows.engine_sent(&segment) {
                self.opens.answered(segment.sport, Instant::now());
            }
        }
        Ok(())
    }
}
impl Drop for NePacketDevice {
    fn drop(&mut self) {
        self.ledger.orphan(&mut self.flows);
    }
}
#[derive(Default)]
struct WorkCount {
    active: AtomicUsize,
}
struct WorkLease {
    count: Arc<WorkCount>,
}
impl Drop for WorkLease {
    fn drop(&mut self) {
        self.count.active.fetch_sub(1, Ordering::AcqRel);
    }
}
struct TrackedWork<'a, T> {
    future: RelayWork<'a, T>,
    _lease: WorkLease,
}
impl<T> Future for TrackedWork<'_, T> {
    type Output = anyhow::Result<T>;
    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().future.as_mut().poll(context)
    }
}
struct TrackedServices {
    inner: Arc<dyn RelayServices>,
    count: Arc<WorkCount>,
}
impl TrackedServices {
    fn track<'a, T: 'a>(&self, make: impl FnOnce() -> RelayWork<'a, T>) -> RelayWork<'a, T> {
        if self
            .count
            .active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                if n < MAX_RELAY_WORK {
                    Some(n + 1)
                } else {
                    None
                }
            })
            .is_err()
        {
            return Box::pin(async { Err(anyhow::anyhow!("owned relay work budget exceeded")) });
        }
        let lease = WorkLease {
            count: self.count.clone(),
        };
        let future = make();
        Box::pin(TrackedWork {
            future,
            _lease: lease,
        })
    }
}
impl EventSink for TrackedServices {
    fn emit(
        &self,
        level: &'static str,
        event: EngineEvent,
        message: &'static str,
        fields: serde_json::Value,
    ) {
        self.inner.emit(level, event, message, fields);
    }
}
impl RelayServices for TrackedServices {
    fn tcp<'a>(
        &'a self,
        local: TcpStream,
        settings: &'a RelaySettings,
        host: String,
        port: u16,
    ) -> RelayWork<'a, ()> {
        self.track(|| self.inner.tcp(local, settings, host, port))
    }
    fn udp_once<'a>(
        &'a self,
        settings: &'a RelaySettings,
        target: ConnectTarget,
        payload: &'a [u8],
    ) -> RelayWork<'a, Vec<u8>> {
        self.track(|| self.inner.udp_once(settings, target, payload))
    }
    fn udp_flow<'a>(
        &'a self,
        settings: &'a RelaySettings,
        host: &'a str,
        port: u16,
        outbound: mpsc::Receiver<Vec<u8>>,
        incoming: mpsc::Sender<UdpPacket>,
    ) -> RelayWork<'a, ()> {
        self.track(|| {
            self.inner
                .udp_flow(settings, host, port, outbound, incoming)
        })
    }
}
/// Actual engine construction values only. Admission must derive these from
/// the unchanged product profile rather than treating this as an authority.
pub struct PacketEngineConfig {
    pub relay: RelaySettings,
    pub max_flows: usize,
    pub idle: Duration,
    pub mtu: usize,
    pub dns_upstream: std::net::SocketAddr,
}
#[derive(Default)]
struct Completion {
    returned: bool,
    expected_cancel: bool,
    stats: Option<TunnelStats>,
    terminal: Option<Result<(), Arc<io::Error>>>,
}
// io::Error is not Clone. Retain the original under Arc so every observation
// reports the same kind and original source rather than consuming it once.
#[derive(Debug)]
struct RetainedError(Arc<io::Error>);
impl std::fmt::Display for RetainedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for RetainedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn observed_error(original: &Arc<io::Error>) -> io::Error {
    io::Error::new(original.kind(), RetainedError(original.clone()))
}
struct SealOnConstructionFailure<'a> {
    bridge: &'a LeasedPacketBridge,
    armed: bool,
}

fn spawn_lease_watchdog(bridge: LeasedPacketBridge) -> io::Result<JoinHandle<()>> {
    thread::Builder::new()
        .name("aegis-ne-lease-watch".into())
        .spawn(move || loop {
            if bridge.probe_lease().is_err() {
                bridge.stop();
                return;
            }
            thread::park_timeout(LEASE_WATCH_INTERVAL);
        })
}
impl Drop for SealOnConstructionFailure<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.bridge.stop();
        }
    }
}

/// Retains the actual worker and injected services while stop observation is
/// unresolved. Observed relay FUTURES are tracked, not arbitrary external work
/// hidden inside an implementation. Credential/renewal/ACK owners belong to the
/// future composite session, so this deliberately does NOT implement EngineOwner.
pub struct PacketEngineOwner {
    worker: ThreadEngine,
    bridge: LeasedPacketBridge,
    watchdog: Option<JoinHandle<()>>,
    watchdog_terminal: Option<Result<(), Arc<io::Error>>>,
    services: Arc<TrackedServices>,
    completion: Arc<Mutex<Completion>>,
    terminal_join_error: Option<Arc<io::Error>>,
}
impl PacketEngineOwner {
    pub fn spawn(
        bridge: LeasedPacketBridge,
        config: PacketEngineConfig,
        services: Arc<dyn RelayServices>,
    ) -> io::Result<Self> {
        Self::spawn_on_ledger(bridge, config, services, flows::FlowLedger::default())
    }
    /// S16o: `spawn`, its device on the epoch's flow `ledger`: the flows its
    /// engine answered go there when it ends, and it resets the orphans of
    /// the epoch's earlier sessions.
    pub(crate) fn spawn_on_ledger(
        bridge: LeasedPacketBridge,
        config: PacketEngineConfig,
        services: Arc<dyn RelayServices>,
        ledger: flows::FlowLedger,
    ) -> io::Result<Self> {
        // Every failed construction path, including invalid config and OS
        // thread-spawn failure, must seal an already admitted packet bridge.
        let mut seal_on_failure = SealOnConstructionFailure {
            bridge: &bridge,
            armed: true,
        };
        if config.max_flows == 0
            || config.max_flows > 512
            || !(1280..=1500).contains(&config.mtu)
            || config.idle == Duration::ZERO
            || config.idle > Duration::from_secs(600)
            || config.dns_upstream.port() == 0
            || config.dns_upstream.ip().is_unspecified()
            || config.dns_upstream.ip().is_multicast()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        bridge.probe_lease()?;
        let services = Arc::new(TrackedServices {
            inner: services,
            count: Arc::new(WorkCount::default()),
        });
        let injected: Arc<dyn RelayServices> = services.clone();
        let completion = Arc::new(Mutex::new(Completion::default()));
        let recorded = completion.clone();
        // Start before the engine: if the watchdog cannot be owned, no packet
        // worker is created. Missing/expired grants close the same bridge even
        // when neither packetFlow nor the engine has another callback.
        let watchdog = spawn_lease_watchdog(bridge.clone())?;
        let worker_bridge = bridge.clone();
        let worker_result = ThreadEngine::spawn(bridge.raw_clone(), move |_raw, stop, ready| {
            let mut device = NePacketDevice::on_ledger(worker_bridge.clone(), stop.clone(), ledger);
            let result = run_ready_with_services(
                &mut device,
                config.relay,
                injected,
                stop.clone(),
                config.max_flows,
                config.idle,
                config.mtu,
                config.dns_upstream,
                || {
                    if ready.send(()).is_err() {
                        stop.store(true, Ordering::Release);
                        worker_bridge.stop();
                    }
                },
            );
            // S16o: the engine's answered flows go to the epoch's ledger as
            // it ends, before its completion is recorded.
            drop(device);
            // Returning from the real library call has dropped its owned Tokio
            // runtime. Only now can the worker record its scoped completion.
            let expected_cancel = result.as_ref().is_err_and(is_cancel_refusal);
            worker_bridge.stop();
            let mut state = recorded.lock().map_err(|_| io::ErrorKind::Other)?;
            state.returned = true;
            state.expected_cancel = expected_cancel;
            match result {
                Ok(stats) => {
                    state.stats = Some(stats);
                    state.terminal = Some(Ok(()));
                    Ok(())
                }
                Err(error) => {
                    let original = Arc::new(error);
                    state.terminal = Some(Err(original.clone()));
                    Err(observed_error(&original))
                }
            }
        });
        let worker = match worker_result {
            Ok(worker) => worker,
            Err(error) => {
                bridge.stop();
                watchdog.thread().unpark();
                let _ = watchdog.join();
                return Err(error);
            }
        };
        seal_on_failure.armed = false;
        drop(seal_on_failure);
        Ok(Self {
            worker,
            bridge,
            watchdog: Some(watchdog),
            watchdog_terminal: None,
            services,
            completion,
            terminal_join_error: None,
        })
    }
    pub fn wait_engine_constructed(&mut self, budget: Duration) -> io::Result<()> {
        self.worker.wait_constructed(budget)
    }
    pub fn engine_constructed(&self) -> bool {
        self.worker.constructed()
    }
    /// This exact packet owner's worker and bridge lease must both be live
    /// before the provider session reports Ready. Authentication remains the
    /// session body's responsibility.
    pub(crate) fn ready_under_lease(&self) -> io::Result<()> {
        if !self.engine_constructed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        self.bridge.probe_lease()
    }
    #[cfg_attr(not(test), allow(dead_code))] // test-side stop of a running owner
    pub(crate) fn stop_handle(&self) -> LeasedPacketBridge {
        self.bridge.clone()
    }
    pub fn cancel(&self) {
        self.bridge.stop();
        if let Some(watchdog) = &self.watchdog {
            watchdog.thread().unpark();
        }
        self.worker.cancel();
    }
    pub fn observed_relay_work(&self) -> usize {
        self.services.count.active.load(Ordering::Acquire)
    }
    pub fn mechanics_joined(&self) -> bool {
        self.worker.joined()
            && self.watchdog_terminal.as_ref().is_some_and(Result::is_ok)
            && self.observed_relay_work() == 0
            && self.completion.lock().is_ok_and(|s| s.returned)
    }
    /// Physical lifetime barrier, including error and panic terminal states.
    /// `mechanics_joined` additionally requires successful bookkeeping, so it
    /// cannot be used to decide when an enclosing Store may be released after
    /// a child failure.
    pub(crate) fn owned_children_joined(&self) -> bool {
        self.worker.joined() && self.watchdog_terminal.is_some() && self.observed_relay_work() == 0
    }
    /// A child or bridge has gone terminal before an external stop request.
    /// The Store supervisor must cancel and join all children on this signal.
    pub(crate) fn terminal_signal_observed(&self) -> bool {
        !self.engine_constructed()
            || self.watchdog.as_ref().is_some_and(JoinHandle::is_finished)
            || self.bridge.is_sealed()
    }
    pub fn try_join(&mut self, budget: Duration) -> io::Result<()> {
        if budget > MAX_JOIN_BUDGET {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let deadline = Instant::now()
            .checked_add(budget)
            .ok_or(io::ErrorKind::InvalidInput)?;
        self.cancel();
        let result = self.worker.try_join(budget);
        if !self.worker.joined() {
            return result;
        }
        while self
            .watchdog
            .as_ref()
            .is_some_and(|watchdog| !watchdog.is_finished())
        {
            if Instant::now() >= deadline {
                return Err(io::ErrorKind::TimedOut.into());
            }
            thread::sleep(Duration::from_millis(1));
        }
        if let Some(watchdog) = self.watchdog.take() {
            self.watchdog_terminal = Some(
                watchdog
                    .join()
                    .map_err(|_| Arc::new(io::Error::other("owned lease watchdog panicked"))),
            );
        }
        if let Some(Err(error)) = &self.watchdog_terminal {
            return Err(observed_error(error));
        }
        if self.observed_relay_work() != 0 {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let state = self.completion.lock().map_err(|_| io::ErrorKind::Other)?;
        if !state.returned {
            drop(state);
            let original = self.terminal_join_error.get_or_insert_with(|| {
                Arc::new(
                    result
                        .err()
                        .unwrap_or_else(|| io::ErrorKind::BrokenPipe.into()),
                )
            });
            return Err(observed_error(original));
        }
        match state.terminal.as_ref() {
            Some(Ok(())) => Ok(()),
            Some(Err(error))
                if state.expected_cancel && error.kind() == io::ErrorKind::NotConnected =>
            {
                Ok(())
            }
            Some(Err(error)) => Err(observed_error(error)),
            None => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
    pub fn take_stats(&mut self) -> io::Result<Option<TunnelStats>> {
        if !self.mechanics_joined() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        Ok(self
            .completion
            .lock()
            .map_err(|_| io::ErrorKind::Other)?
            .stats
            .take())
    }
}
impl Drop for PacketEngineOwner {
    fn drop(&mut self) {
        self.bridge.stop();
        if let Some(watchdog) = self.watchdog.take() {
            watchdog.thread().unpark();
            if watchdog.is_finished() {
                let _ = watchdog.join();
            }
        }
    }
}
#[cfg(test)]
#[path = "packet_engine_burst_tests.rs"]
mod burst_tests;
#[path = "packet_engine_flows.rs"]
pub(crate) mod flows;
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::PacketBridge;
    use aegis_client::capture_lease_gate::CaptureLeaseDeadline;
    use std::sync::atomic::AtomicU64;

    fn assert_unclassified_bridge_stop(error: &io::Error) {
        let cause = match error.kind() {
            io::ErrorKind::NotConnected => io::Error::from(io::ErrorKind::NotConnected).to_string(),
            io::ErrorKind::PermissionDenied => "worker capture lease missing".to_string(),
            other => panic!("unexpected bridge stop error: {other:?}: {error}"),
        };
        assert_eq!(error.to_string(), cause);
        assert!(!is_cancel_refusal(error));
    }

    fn config() -> PacketEngineConfig {
        PacketEngineConfig {
            relay: RelaySettings::default(),
            max_flows: 2,
            idle: Duration::from_secs(1),
            mtu: 1280,
            dns_upstream: "127.0.0.1:9".parse().unwrap(),
        }
    }

    fn admitted_bridge() -> LeasedPacketBridge {
        // Inert mechanics fixture. A production session must obtain this
        // deadline from its authenticated policy ACK owner.
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(u64::MAX)).unwrap();
        LeasedPacketBridge::new(PacketBridge::default(), deadline)
    }
    struct NoNetwork;
    impl EventSink for NoNetwork {
        fn emit(&self, _: &'static str, _: EngineEvent, _: &'static str, _: serde_json::Value) {}
    }
    impl RelayServices for NoNetwork {
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
    fn packet() -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&20u16.to_be_bytes());
        p
    }
    #[test]
    fn actual_packetio_uses_bounded_bridge_and_stop_discards_queues() {
        let bridge = admitted_bridge();
        let stop = Arc::new(AtomicBool::new(false));
        let mut device = NePacketDevice::new(bridge.clone(), stop.clone());
        bridge.from_os(&packet()).unwrap();
        assert_eq!(device.receive().unwrap(), Some(packet()));
        device.send(&packet()).unwrap();
        assert_eq!(bridge.to_os().unwrap(), Some(packet()));
        for _ in 0..128 {
            device.send(&packet()).unwrap();
        }
        // A full output queue is backpressure the engine drops and counts.
        assert_eq!(
            device.send(&packet()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        assert_eq!(bridge.dropped_outbound(), 1);
        assert_eq!(bridge.to_os().unwrap(), Some(packet()));
        stop.store(true, Ordering::Release);
        assert!(device.receive().is_err());
    }
    #[test]
    fn actual_queue_failure_stays_error_after_late_cancel() {
        let bridge = admitted_bridge();
        let stop = Arc::new(AtomicBool::new(false));
        let mut device = NePacketDevice::new(bridge.clone(), stop.clone());
        for _ in 0..128 {
            device.send(&packet()).unwrap();
        }
        assert_eq!(
            device.send(&packet()).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        // An invalid packet is the queue failure that seals.
        let queue_failure = device.send(&[0x45]).unwrap_err();
        assert_eq!(queue_failure.kind(), io::ErrorKind::NotConnected);
        assert!(!is_cancel_refusal(&queue_failure));
        // Controlled late cancellation occurs only AFTER the actual queue failure
        // result exists, reproducing the old post-return stop-load race.
        stop.store(true, Ordering::Release);
        assert!(!is_cancel_refusal(&queue_failure));
        let stopped_operation = device.receive().unwrap_err();
        assert!(is_cancel_refusal(&stopped_operation));
        assert!(!is_cancel_refusal(&io::Error::from(
            io::ErrorKind::NotConnected
        )));
    }
    #[test]
    fn actual_seal_and_revocation_keep_distinct_errors_after_late_cancel() {
        for expected in [io::ErrorKind::NotConnected, io::ErrorKind::PermissionDenied] {
            let deadline = CaptureLeaseDeadline::default();
            deadline.replace(Some(u64::MAX)).unwrap();
            let raw = PacketBridge::default();
            let bridge = LeasedPacketBridge::new(raw.clone(), deadline.clone());
            let stop = Arc::new(AtomicBool::new(false));
            let mut device = NePacketDevice::new(bridge, stop.clone());
            if expected == io::ErrorKind::NotConnected {
                raw.stop();
            } else {
                deadline.replace(None).unwrap();
            }
            let failure = device.receive().unwrap_err();
            // Exercise each actual guard before the stop flag can be observed.
            // Revocation and a sealed queue retain different original causes.
            assert_eq!(failure.kind(), expected);
            assert_unclassified_bridge_stop(&failure);
            stop.store(true, Ordering::Release);
            assert_eq!(failure.kind(), expected);
            assert_unclassified_bridge_stop(&failure);
            assert!(is_cancel_refusal(&device.receive().unwrap_err()));
        }
    }
    #[test]
    fn actual_tokio_cancel_drops_counted_relay_future() {
        let count = Arc::new(WorkCount::default());
        let services = Arc::new(TrackedServices {
            inner: Arc::new(NoNetwork),
            count: count.clone(),
        });
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), async {
                let task = tokio::spawn(async move {
                    let settings = RelaySettings::default();
                    services
                        .udp_once(
                            &settings,
                            ConnectTarget {
                                host: "127.0.0.1".into(),
                                port: 9,
                            },
                            b"fixture",
                        )
                        .await
                });
                while count.active.load(Ordering::Acquire) == 0 {
                    tokio::task::yield_now().await;
                }
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
                assert_eq!(count.active.load(Ordering::Acquire), 0);
            })
            .await
            .unwrap();
        });
    }
    #[test]
    fn actual_shared_engine_constructs_and_owned_cancel_joins_without_network() {
        let mut owner = PacketEngineOwner::spawn(
            admitted_bridge(),
            PacketEngineConfig {
                relay: RelaySettings::default(),
                max_flows: 2,
                idle: Duration::from_secs(1),
                mtu: 1280,
                dns_upstream: "127.0.0.1:9".parse().unwrap(),
            },
            Arc::new(NoNetwork),
        )
        .unwrap();
        assert_eq!(
            owner.ready_under_lease().unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        owner
            .wait_engine_constructed(Duration::from_secs(2))
            .unwrap();
        assert!(owner.engine_constructed());
        owner.ready_under_lease().unwrap();
        owner.stop_handle().stop();
        assert!(owner.ready_under_lease().is_err());
        let joined = owner.try_join(Duration::from_secs(2));
        // The raw queue seal and lease revocation are observed at separate
        // guards. Preserve the exact original guard error after late cancel,
        // even though the worker and watchdog were physically joined.
        if let Err(error) = joined {
            assert_unclassified_bridge_stop(&error);
        }
        assert!(owner.mechanics_joined());
        assert!(owner.ready_under_lease().is_err());
        assert_eq!(owner.observed_relay_work(), 0);
        let _scoped_stats = owner.take_stats().unwrap();
    }

    #[test]
    fn absent_lease_refuses_worker_before_construction() {
        let bridge =
            LeasedPacketBridge::new(PacketBridge::default(), CaptureLeaseDeadline::default());
        let error = PacketEngineOwner::spawn(bridge.clone(), config(), Arc::new(NoNetwork))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(bridge.is_sealed());
    }

    #[test]
    fn invalid_config_seals_previously_leased_queued_output() {
        let bridge = admitted_bridge();
        let raw = bridge.raw_clone();
        bridge.engine_send(&packet()).unwrap();
        let mut invalid = config();
        invalid.max_flows = 0;
        let error = PacketEngineOwner::spawn(bridge.clone(), invalid, Arc::new(NoNetwork))
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(bridge.is_sealed());
        assert_eq!(raw.to_os().unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn oversized_join_budget_returns_error_without_cancel_or_panic() {
        let bridge = admitted_bridge();
        let mut owner =
            PacketEngineOwner::spawn(bridge.clone(), config(), Arc::new(NoNetwork)).unwrap();
        owner
            .wait_engine_constructed(Duration::from_secs(2))
            .unwrap();
        assert_eq!(
            owner.try_join(Duration::MAX).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert!(!bridge.is_sealed());
        let joined = owner.try_join(Duration::from_secs(2));
        if let Err(error) = joined {
            assert_unclassified_bridge_stop(&error);
        }
        assert!(owner.mechanics_joined());
    }

    #[test]
    fn standalone_watchdog_seals_idle_clock_failure_without_engine_callback() {
        let failed = Arc::new(AtomicBool::new(false));
        let clock_failed = failed.clone();
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let raw = PacketBridge::default();
        let bridge = LeasedPacketBridge::with_clock(raw.clone(), deadline, move || {
            if clock_failed.load(Ordering::SeqCst) {
                Err(io::Error::other("inert clock failure"))
            } else {
                Ok(10)
            }
        });
        bridge.engine_send(&packet()).unwrap();
        let watchdog = spawn_lease_watchdog(bridge.clone()).unwrap();
        failed.store(true, Ordering::SeqCst);
        watchdog.thread().unpark();
        let end = Instant::now() + Duration::from_secs(2);
        while !watchdog.is_finished() {
            assert!(Instant::now() < end, "clock failure watchdog did not exit");
            thread::sleep(Duration::from_millis(2));
        }
        watchdog.join().unwrap();
        assert!(bridge.is_sealed());
        assert_eq!(raw.to_os().unwrap_err().kind(), io::ErrorKind::NotConnected);
    }

    #[test]
    fn idle_expired_lease_seals_queued_output_and_owned_watchdog_joins() {
        let now = Arc::new(AtomicU64::new(10));
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(20)).unwrap();
        let clock = now.clone();
        let raw = PacketBridge::default();
        let bridge = LeasedPacketBridge::with_clock(raw.clone(), deadline, move || {
            Ok(clock.load(Ordering::SeqCst))
        });
        bridge.engine_send(&packet()).unwrap();
        let mut owner =
            PacketEngineOwner::spawn(bridge.clone(), config(), Arc::new(NoNetwork)).unwrap();
        owner
            .wait_engine_constructed(Duration::from_secs(2))
            .unwrap();
        now.store(20, Ordering::SeqCst);
        let end = Instant::now() + Duration::from_secs(2);
        while !bridge.is_sealed() {
            assert!(Instant::now() < end, "idle deadline was not sealed");
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(raw.to_os().unwrap_err().kind(), io::ErrorKind::NotConnected);
        let joined = owner.try_join(Duration::from_secs(2));
        if let Err(error) = joined {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::NotConnected | io::ErrorKind::PermissionDenied
            ));
        }
        assert!(owner.mechanics_joined());
    }

    #[test]
    fn idle_direct_revocation_is_sealed_without_packet_callback() {
        let deadline = CaptureLeaseDeadline::default();
        deadline.replace(Some(u64::MAX)).unwrap();
        let raw = PacketBridge::default();
        let bridge = LeasedPacketBridge::new(raw.clone(), deadline.clone());
        bridge.engine_send(&packet()).unwrap();
        let mut owner =
            PacketEngineOwner::spawn(bridge.clone(), config(), Arc::new(NoNetwork)).unwrap();
        owner
            .wait_engine_constructed(Duration::from_secs(2))
            .unwrap();
        deadline.replace(None).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        while !bridge.is_sealed() {
            assert!(Instant::now() < end, "idle revocation was not sealed");
            thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(raw.to_os().unwrap_err().kind(), io::ErrorKind::NotConnected);
        let joined = owner.try_join(Duration::from_secs(2));
        if let Err(error) = joined {
            assert!(matches!(
                error.kind(),
                io::ErrorKind::NotConnected | io::ErrorKind::PermissionDenied
            ));
        }
        assert!(owner.mechanics_joined());
    }
    #[test]
    fn actual_non_cancel_bridge_failure_remains_error_after_repeated_join() {
        let bridge = admitted_bridge();
        let mut owner = PacketEngineOwner::spawn(
            bridge.clone(),
            PacketEngineConfig {
                relay: RelaySettings::default(),
                max_flows: 2,
                idle: Duration::from_secs(1),
                mtu: 1280,
                dns_upstream: "127.0.0.1:9".parse().unwrap(),
            },
            Arc::new(NoNetwork),
        )
        .unwrap();
        owner
            .wait_engine_constructed(Duration::from_secs(2))
            .unwrap();
        // Seal the bridge while the worker stop flag remains false. Wait for the
        // real engine to return before try_join asks ThreadEngine to cancel.
        bridge.stop();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !<ThreadEngine as crate::bridge::EngineOwner>::terminal(&owner.worker) {
            assert!(
                std::time::Instant::now() < deadline,
                "engine did not finish after bridge seal"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(!owner.completion.lock().unwrap().expected_cancel);
        let first = owner.try_join(Duration::from_secs(2)).unwrap_err();
        let second = owner.try_join(Duration::from_secs(2)).unwrap_err();
        assert_unclassified_bridge_stop(&first);
        assert_eq!(second.kind(), first.kind());
        assert_eq!(second.to_string(), first.to_string());
        assert!(!is_cancel_refusal(&first));
        assert!(!is_cancel_refusal(&second));
        assert!(owner.mechanics_joined());
        assert!(owner.owned_children_joined());
        assert_eq!(
            owner.try_join(Duration::ZERO).unwrap_err().kind(),
            first.kind()
        );
    }
    #[test]
    fn actual_worker_panic_cause_remains_error_after_repeated_join() {
        let worker = ThreadEngine::spawn(
            PacketBridge::default(),
            |_bridge, _stop, _ready| -> io::Result<()> { panic!("inert worker failure") },
        )
        .unwrap();
        let services = Arc::new(TrackedServices {
            inner: Arc::new(NoNetwork),
            count: Arc::new(WorkCount::default()),
        });
        let mut owner = PacketEngineOwner {
            worker,
            bridge: admitted_bridge(),
            watchdog: None,
            watchdog_terminal: Some(Ok(())),
            services,
            completion: Arc::new(Mutex::new(Completion::default())),
            terminal_join_error: None,
        };
        let first = owner.try_join(Duration::from_secs(2)).unwrap_err();
        let second = owner.try_join(Duration::from_secs(2)).unwrap_err();
        assert_eq!(first.kind(), io::ErrorKind::Other);
        assert_eq!(second.kind(), first.kind());
        assert_eq!(second.to_string(), first.to_string());
        assert_eq!(first.to_string(), "owned engine panicked");
        assert!(!owner.mechanics_joined());
        assert!(owner.owned_children_joined());
        assert_eq!(
            owner.try_join(Duration::ZERO).unwrap_err().to_string(),
            "owned engine panicked"
        );
    }
}
