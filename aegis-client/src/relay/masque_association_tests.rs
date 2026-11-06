use super::*;
use aegis_core::{RelaySettings, TunnelTransportFamily};
use aegis_server::config::{ServerConfig, TargetPolicyConfig, TargetPolicyProfile};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

// Sole paired diagnostic seam. No production clock or deadline is changed.
const IDLE_CLOCK_AUTO_ADVANCE_HOLD: bool = true;

#[derive(Default)]
struct IdleClockState {
    phase: &'static str,
    started: bool,
    resumed: bool,
    expected_ns: u128,
    observed_ns: u128,
    drift: bool,
    manual_jump_in_progress: bool,
    manual_jump_interrupted: bool,
    observations: usize,
    first_generation: Option<u64>,
    first_generation_preserved: bool,
    replacement_proven: bool,
}
#[derive(Default)]
struct IdleClockProbe(std::sync::Mutex<IdleClockState>);
impl IdleClockProbe {
    fn state(&self) -> std::sync::MutexGuard<'_, IdleClockState> {
        self.0.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn phase(&self, phase: &'static str) {
        self.state().phase = phase;
    }
    fn begin_manual_jump(&self, phase: &'static str) {
        let mut state = self.state();
        assert!(
            !state.manual_jump_in_progress,
            "nested manual idle clock jump"
        );
        state.phase = phase;
        state.manual_jump_in_progress = true;
    }
    fn observe(&self, phase: &'static str, origin: Instant, expected: Duration) {
        let mut state = self.state();
        state.phase = phase;
        state.manual_jump_in_progress = false;
        state.expected_ns = expected.as_nanos();
        state.observed_ns = origin.elapsed().as_nanos();
        state.drift |= state.observed_ns != state.expected_ns;
        state.observations += 1;
        assert_eq!(
            state.observed_ns, state.expected_ns,
            "idle fixture clock advanced outside its original manual jumps"
        );
    }
    fn first(&self, association: &AssociationProbe) {
        let source = association.state();
        let first = &source.slots[0];
        assert!(first.live && first.admissions == 1 && first.generation.is_some());
        self.state().first_generation = first.generation;
    }
    fn preserved(&self, association: &AssociationProbe) {
        let source = association.state();
        let first = &source.slots[0];
        let mut state = self.state();
        assert!(first.live && first.admissions == 1 && first.generation == state.first_generation);
        state.first_generation_preserved = true;
    }
    fn replaced(&self, association: &AssociationProbe) {
        let source = association.state();
        let first = &source.slots[0];
        let mut state = self.state();
        assert!(first.live && first.admissions == 2 && first.generation != state.first_generation);
        state.replacement_proven = true;
    }
    fn report(&self, wall_complete: bool, cleanup: bool, hold_joined: bool, hold_released: bool) {
        let state = self.state();
        eprintln!("masque_idle_clock_phase phase={} expected_ns={} observed_ns={} clock_drift={} manual_jump_in_progress={} manual_jump_interrupted={} observations={} started={} resumed={} first_generation_preserved={} replacement_proven={} wall_complete={} clock_hold={} hold_joined={} hold_released={} cleanup_confirmed={}",
            state.phase, state.expected_ns, state.observed_ns, state.drift,
            state.manual_jump_in_progress, state.manual_jump_interrupted, state.observations,
            state.started, state.resumed, state.first_generation_preserved, state.replacement_proven,
            wall_complete, IDLE_CLOCK_AUTO_ADVANCE_HOLD, hold_joined, hold_released, cleanup);
    }
}

// Locked Tokio1.53.2 schedules a current-thread blocking owner with
// auto-advance inhibited. Its channel wait ends at the ORIGINAL native cutoff,
// not a fresh timeout. The exterior parent always releases and awaits it.
struct IdleClockHold {
    stop: Option<std::sync::mpsc::Sender<()>>,
    owner: OwnedJoin<bool>,
}
impl IdleClockHold {
    fn new(end: std::time::Instant) -> Self {
        let (stop, stopped) = std::sync::mpsc::channel();
        let handle = tokio::task::spawn_blocking(move || {
            stopped
                .recv_timeout(end.saturating_duration_since(std::time::Instant::now()))
                .is_ok()
        });
        Self {
            stop: Some(stop),
            owner: OwnedJoin {
                handle,
                joined: false,
            },
        }
    }
    fn release(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
    }
}
impl Drop for IdleClockHold {
    fn drop(&mut self) {
        // Disconnect wakes a running receive. OwnedJoin requests cancellation
        // of a still-queued task; Drop does not claim a joined blocking owner.
        self.stop.take();
    }
}

struct PausedClock {
    origin: Instant,
    probe: std::sync::Arc<IdleClockProbe>,
}
impl PausedClock {
    fn new(probe: std::sync::Arc<IdleClockProbe>) -> Self {
        tokio::time::pause();
        probe.state().started = true;
        Self {
            origin: Instant::now(),
            probe,
        }
    }
}
impl Drop for PausedClock {
    fn drop(&mut self) {
        // Capture unexpected auto-advance even when an original real I/O await
        // stalls and the native watchdog aborts this body before the next check.
        {
            let mut state = self.probe.state();
            state.observed_ns = self.origin.elapsed().as_nanos();
            if state.manual_jump_in_progress {
                // Abortion between the original advance/yield and its observation
                // is an interrupted intentional jump, not auto-advance evidence.
                state.manual_jump_interrupted = true;
            } else {
                state.drift |= state.observed_ns != state.expected_ns;
            }
        }
        tokio::time::resume();
        self.probe.state().resumed = true;
    }
}

// Same original20s native watchdog, with explicit exterior custody on failures.
// Only the final cleanup has a distinct500ms allowance. Its Tokio clock is
// restored by the body's PausedClock Drop before any cleanup timer is created.
async fn wall_bounded<F>(
    future: F,
    custody: std::sync::Arc<CaseCustody>,
    association_probe: std::sync::Arc<AssociationProbe>,
    clock_probe: std::sync::Arc<IdleClockProbe>,
    end: std::time::Instant,
    mut hold: Option<IdleClockHold>,
) where
    F: std::future::Future<Output = Fixture> + Send + 'static,
{
    let mut body = OwnedJoin {
        handle: tokio::spawn(future),
        joined: false,
    };
    let abort = body.handle.abort_handle();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let watchdog = std::thread::spawn(move || {
        if done_rx
            .recv_timeout(end.saturating_duration_since(std::time::Instant::now()))
            .is_err()
        {
            abort.abort();
            false
        } else {
            true
        }
    });
    let result = (&mut body.handle).await;
    body.joined = true;
    let _ = done_tx.send(());
    let wall_complete = watchdog.join().unwrap_or(false);
    let body_success = result.is_ok();
    let _fixture = result.ok();
    let clock_restored = {
        let state = clock_probe.state();
        !state.started || state.resumed
    };
    let mut children = custody.take();
    let mut association_success = false;
    if body_success && wall_complete && clock_restored {
        if let Some(child) = children
            .iter_mut()
            .find(|child| child.kind == ChildKind::Association)
        {
            let original_remaining = end.saturating_duration_since(std::time::Instant::now());
            let join_end = Instant::now() + original_remaining;
            let result = tokio::time::timeout_at(join_end, &mut child.owner.handle).await;
            child.owner.joined = result.is_ok();
            association_success = matches!(result, Ok(Ok(Ok(()))));
        }
    }
    if let Some(hold) = &mut hold {
        hold.release();
    }
    let cleanup_end = Instant::now() + Duration::from_millis(500);
    // A failed body drops its real control peer. Give the original association
    // time to join its target JoinSet, always within this fixed cleanup cutoff.
    for child in &mut children {
        if child.kind == ChildKind::Association && !child.owner.joined {
            child.owner.joined = tokio::time::timeout_at(cleanup_end, &mut child.owner.handle)
                .await
                .is_ok();
        }
    }
    for child in &children {
        if !child.owner.joined {
            child.owner.handle.abort();
        }
    }
    for child in &mut children {
        if !child.owner.joined {
            child.owner.joined = tokio::time::timeout_at(cleanup_end, &mut child.owner.handle)
                .await
                .is_ok();
        }
    }
    let (hold_joined, hold_released) = match &mut hold {
        Some(hold) => {
            let result = tokio::time::timeout_at(cleanup_end, &mut hold.owner.handle).await;
            hold.owner.joined = result.is_ok();
            (hold.owner.joined, matches!(result, Ok(Ok(true))))
        }
        None => (true, true),
    };
    let association_present = children
        .iter()
        .any(|child| child.kind == ChildKind::Association);
    let descendant_join = !association_present || association_probe.state().shutdown_joined;
    let cleanup = body.joined
        && clock_restored
        && children.iter().all(|child| child.owner.joined)
        && descendant_join
        && hold_joined;
    clock_probe.report(wall_complete, cleanup, hold_joined, hold_released);
    assert!(
        cleanup,
        "INVALID: idle fixture clock/task cleanup unconfirmed within separate500ms allowance"
    );
    assert!(
        wall_complete
            && body_success
            && association_success
            && children.len() == 2
            && hold_released,
        "bounded original authenticated idle/reopen fixture failed"
    );
    let state = clock_probe.state();
    assert!(
        !state.drift && state.first_generation_preserved && state.replacement_proven,
        "idle/reopen fixture lacked original clock and generation validity"
    );
}

struct Fixture {
    _dir: tempfile::TempDir,
    settings: RelaySettings,
    server: Option<JoinHandle<anyhow::Result<()>>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = &self.server {
            server.abort();
        }
    }
}

impl Fixture {
    async fn start() -> Self {
        Self::start_with_custody(None).await
    }

    async fn start_with_custody(custody: Option<&CaseCustody>) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = tempfile::tempdir().unwrap();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        #[cfg(not(windows))]
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();
        #[cfg(windows)]
        aegis_core::windows_file::write_private_new(
            &key_path,
            cert.key_pair.serialize_pem().as_bytes(),
            false,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let tcp_probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp = tcp_probe.local_addr().unwrap();
        drop(tcp_probe);
        let udp_probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp = udp_probe.local_addr().unwrap();
        drop(udp_probe);
        let mut config = ServerConfig {
            listen: tcp.to_string(),
            cert: cert_path.clone(),
            key: key_path,
            auth_token: "a22a0b4c4bcf6b5850b02bab7c02a24046df90886085389fc8350f2d311ba32b".into(),
            target_policy: TargetPolicyConfig {
                profile: TargetPolicyProfile::FullVpnEgress,
                allowed_ports: Vec::new(),
            },
            legacy_auth_tokens: Vec::new(),
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            transport: Default::default(),
            bundle_endpoint: Default::default(),
        };
        config.transport.quic_listen = Some(udp.to_string());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let future =
            aegis_server::run_server_with_shutdown(config, Some(ready_tx), std::future::pending());
        // Register the server with the exterior parent before awaiting readiness.
        // The ordinary fixtures retain their previous local owner and Drop abort.
        let server = match custody {
            Some(custody) => {
                custody.spawn(ChildKind::Server, future);
                None
            }
            None => Some(tokio::spawn(future)),
        };
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        Self {
            _dir: dir,
            settings: RelaySettings {
                server: tcp.to_string(),
                server_name: "localhost".into(),
                auth_token: "a22a0b4c4bcf6b5850b02bab7c02a24046df90886085389fc8350f2d311ba32b"
                    .into(),
                ca_cert: Some(cert_path),
                masque_trust_mode: aegis_core::MasqueTrustMode::ConfiguredCaOnly,
                transport_priority: vec![TunnelTransportFamily::GrpcStream],
                udp_transport_priority: Some(vec![TunnelTransportFamily::MasqueDerived]),
                masque_server: Some(udp.to_string()),
                connect_timeout_ms: 1500,
                ..Default::default()
            },
            server,
        }
    }
}

async fn association(
    settings: RelaySettings,
) -> (
    TcpStream,
    UdpSocket,
    SocketAddr,
    JoinHandle<anyhow::Result<()>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (control, _) = listener.accept().await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        run_udp_association(
            UdpSessionControl::SocksControl(control),
            socket,
            &settings,
            &policy::RelaySessionProfile::default(),
            super::super::TunnelTransportFamily::MasqueDerived,
            "127.0.0.1".parse().unwrap(),
        )
        .await
    });
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (control_peer, app, address, task)
}

// Per-association test observations. Targets remain in memory; diagnostics print
// only static phases and bounded counts. This does not admit or retry a packet.
#[derive(Default)]
struct ProbeSlot {
    target: Option<ConnectTarget>,
    generation: Option<u64>,
    admissions: usize,
    live: bool,
    delivered: bool,
}

// Bounded test-only observations. Never retain payload, peer or error text.
#[derive(Default)]
struct OriginalCaseObservation {
    deadline: Option<Instant>,
    wall_origin: Option<std::time::Instant>,
    absence_started: bool,
    remaining_ns_at_absence: Option<u128>,
    wall_elapsed_ns_at_absence: Option<u128>,
    absence_result: Option<&'static str>,
    absence_datagram_bytes: usize,
    absence_io_error_kind: Option<&'static str>,
    absence_os_error: Option<i32>,
    body_result: Option<&'static str>,
    association_result: Option<&'static str>,
}

struct ProbeState {
    slots: [ProbeSlot; 129],
    phase: &'static str,
    sent: usize,
    maximum_live: usize,
    refused_slot: Option<usize>,
    refused_live: usize,
    refused_full_original_map: bool,
    cap_first_generation: Option<u64>,
    refusal_count: usize,
    existing_first_queued: usize,
    unexpected: bool,
    validity_complete: bool,
    control_closed: bool,
    shutdown_joined: bool,
    original: OriginalCaseObservation,
}

pub(super) struct AssociationProbe {
    state: std::sync::Mutex<ProbeState>,
    changed: tokio::sync::Notify,
}

impl AssociationProbe {
    fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(ProbeState {
                slots: std::array::from_fn(|_| ProbeSlot::default()),
                phase: "created",
                sent: 0,
                maximum_live: 0,
                refused_slot: None,
                refused_live: 0,
                refused_full_original_map: false,
                cap_first_generation: None,
                refusal_count: 0,
                existing_first_queued: 0,
                unexpected: false,
                validity_complete: false,
                control_closed: false,
                shutdown_joined: false,
                original: OriginalCaseObservation::default(),
            }),
            changed: tokio::sync::Notify::new(),
        }
    }
    fn state(&self) -> std::sync::MutexGuard<'_, ProbeState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
    fn phase(&self, phase: &'static str) {
        self.state().phase = phase;
    }
    fn expect_target(&self, index: usize, target: ConnectTarget) {
        let mut state = self.state();
        assert!(index < 129 && state.slots[index].target.is_none());
        state.slots[index].target = Some(target);
    }
    fn sent(&self) {
        self.state().sent += 1;
    }
    pub(super) fn admitted(&self, target: &ConnectTarget, generation: u64, live: usize) {
        let mut state = self.state();
        if let Some(index) = state
            .slots
            .iter()
            .position(|slot| slot.target.as_ref() == Some(target))
        {
            let slot = &mut state.slots[index];
            slot.generation = Some(generation);
            slot.admissions += 1;
            slot.live = true;
            state.maximum_live = state.maximum_live.max(live);
        } else {
            state.unexpected = true;
        }
    }
    pub(super) fn retired(&self, target: &ConnectTarget, generation: u64) {
        let mut state = self.state();
        if let Some(slot) = state
            .slots
            .iter_mut()
            .find(|slot| slot.target.as_ref() == Some(target))
        {
            if slot.generation == Some(generation) {
                slot.live = false;
            }
        } else {
            state.unexpected = true;
        }
    }
    pub(super) fn refused_at_cap(&self, target: &ConnectTarget, live: usize) {
        let mut state = self.state();
        state.refusal_count += 1;
        state.refused_slot = state
            .slots
            .iter()
            .position(|slot| slot.target.as_ref() == Some(target));
        state.refused_live = live;
        state.refused_full_original_map = live == 128
            && state.slots[..128]
                .iter()
                .all(|slot| slot.live && slot.admissions == 1)
            && state.slots[128].admissions == 0;
        state.cap_first_generation = state.slots[0].generation;
        drop(state);
        self.changed.notify_one();
    }
    pub(super) fn existing_queued(&self, target: &ConnectTarget, generation: u64) {
        let mut state = self.state();
        if state.slots[0].target.as_ref() == Some(target)
            && state.slots[0].generation == Some(generation)
        {
            state.existing_first_queued += 1;
        }
    }
    pub(super) fn control_closed(&self) {
        self.state().control_closed = true;
    }
    pub(super) fn shutdown_joined(&self) {
        self.state().shutdown_joined = true;
    }
    async fn cap_refusal(&self) {
        loop {
            let notified = self.changed.notified();
            if self.state().refusal_count != 0 {
                break;
            }
            notified.await;
        }
        let state = self.state();
        assert!(!state.unexpected && state.refusal_count == 1);
        assert_eq!(state.refused_slot, Some(128));
        assert_eq!(state.refused_live, 128);
        assert!(
            state.refused_full_original_map,
            "actual original 128-entry map at refusal"
        );
    }
    fn delivered(&self, index: usize) {
        self.state().slots[index].delivered = true;
    }
    fn complete_validity(&self) {
        let mut state = self.state();
        assert!(!state.unexpected && state.sent == 129 && state.maximum_live == 128);
        // The production cap counts pending/opening entries too. Its original
        // 128-entry snapshot is required, not unrelated egress delivery on the
        // other 127 targets. Target zero remains the real authenticated control.
        assert!(state.refused_full_original_map && state.slots[128].admissions == 0);
        let first = &state.slots[0];
        assert!(
            first.live
                && first.admissions == 1
                && first.generation.is_some()
                && first.generation == state.cap_first_generation
                && first.delivered,
            "established first target retains its original generation at the cap"
        );
        state.validity_complete = true;
    }
    fn successful_post_cap_echo(&self) {
        let state = self.state();
        let first = &state.slots[0];
        assert!(
            state.validity_complete
                && first.live
                && first.admissions == 1
                && first.generation == state.cap_first_generation
                && state.existing_first_queued > 0,
            "authenticated post-cap echo uses the same existing first generation"
        );
    }
    fn successful_original_shutdown(&self) {
        let state = self.state();
        assert!(state.validity_complete && state.control_closed && state.shutdown_joined);
    }
    fn original_case_deadline(&self, end: Instant) {
        let mut state = self.state();
        state.original.deadline = Some(end);
        state.original.wall_origin = Some(std::time::Instant::now());
    }
    fn original_absence_started(&self) {
        let mut state = self.state();
        let original = &mut state.original;
        original.absence_started = true;
        original.remaining_ns_at_absence = original
            .deadline
            .map(|end| end.saturating_duration_since(Instant::now()).as_nanos());
        original.wall_elapsed_ns_at_absence =
            original.wall_origin.map(|start| start.elapsed().as_nanos());
    }
    fn original_absence_result(
        &self,
        result: &std::result::Result<
            std::io::Result<(usize, SocketAddr)>,
            tokio::time::error::Elapsed,
        >,
    ) {
        let mut state = self.state();
        let original = &mut state.original;
        original.absence_result = Some(match result {
            Err(_) => "outer_timeout",
            Ok(Ok((bytes, _))) => {
                original.absence_datagram_bytes = *bytes;
                "udp_datagram"
            }
            Ok(Err(error)) => {
                original.absence_io_error_kind = Some(match error.kind() {
                    std::io::ErrorKind::ConnectionReset => "connection_reset",
                    std::io::ErrorKind::ConnectionAborted => "connection_aborted",
                    std::io::ErrorKind::TimedOut => "timed_out",
                    std::io::ErrorKind::WouldBlock => "would_block",
                    std::io::ErrorKind::Interrupted => "interrupted",
                    std::io::ErrorKind::PermissionDenied => "permission_denied",
                    _ => "other",
                });
                original.absence_os_error = error.raw_os_error();
                "udp_io_error"
            }
        });
    }
    fn original_body_result<T>(
        &self,
        result: &std::result::Result<
            std::result::Result<T, tokio::task::JoinError>,
            tokio::time::error::Elapsed,
        >,
    ) {
        self.state().original.body_result = Some(match result {
            Ok(Ok(_)) => "completed",
            Ok(Err(error)) if error.is_panic() => "panicked",
            Ok(Err(error)) if error.is_cancelled() => "cancelled",
            Ok(Err(_)) => "join_error",
            Err(_) => "deadline_elapsed",
        });
    }
    fn original_association_result(
        &self,
        result: &std::result::Result<
            std::result::Result<anyhow::Result<()>, tokio::task::JoinError>,
            tokio::time::error::Elapsed,
        >,
    ) {
        self.state().original.association_result = Some(match result {
            Ok(Ok(Ok(()))) => "completed_ok",
            Ok(Ok(Err(_))) => "completed_err",
            Ok(Err(_)) => "join_error",
            Err(_) => "deadline_elapsed",
        });
    }
    fn report_original_results(&self) {
        // The exterior owner calls this ONLY after original cleanup attempts.
        // body_joined after cancellation is not an original-body success claim.
        let state = self.state();
        let original = &state.original;
        eprintln!("masque_original_results deadline_present={} absence_started={} remaining_ns_at_absence={} wall_elapsed_ns_at_absence={} absence_result={} absence_datagram_bytes={} absence_io_error_kind={} absence_os_error_present={} absence_os_error={} body_result={} association_result={}",
            original.deadline.is_some(), original.absence_started,
            original.remaining_ns_at_absence.unwrap_or(0), original.wall_elapsed_ns_at_absence.unwrap_or(0),
            original.absence_result.unwrap_or("not_observed"), original.absence_datagram_bytes,
            original.absence_io_error_kind.unwrap_or("not_observed"), original.absence_os_error.is_some(),
            original.absence_os_error.unwrap_or(0), original.body_result.unwrap_or("not_observed"),
            original.association_result.unwrap_or("not_polled_due_body_failure"));
    }

    fn report(&self, body_joined: bool, children_joined: usize, child_count: usize, cleanup: bool) {
        let state = self.state();
        // Output happens after cleanup observations, never before aborting a child.
        eprintln!("masque_association_phase phase={} sent={} admitted={} delivered={} max_live={} cap_live={} cap_valid={} established_first={} other_target_delivery=not_required_not_measured validity={} control={} shutdown={} body_joined={} children_joined={} children={} cleanup_confirmed={}",
            state.phase, state.sent,
            state.slots.iter().filter(|slot| slot.admissions != 0).count(),
            state.slots.iter().filter(|slot| slot.delivered).count(), state.maximum_live,
            state.refused_live, state.refused_full_original_map,
            state.slots[0].delivered, state.validity_complete,
            state.control_closed, state.shutdown_joined, body_joined, children_joined,
            child_count, cleanup);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ChildKind {
    Server,
    Association,
}

// Drop is a cancellation request, never a joined/reaped claim. The exterior
// parent retains this guard through timeout_at(&mut handle), and records joins.
struct OwnedJoin<T> {
    handle: JoinHandle<T>,
    joined: bool,
}
impl<T> Drop for OwnedJoin<T> {
    fn drop(&mut self) {
        if !self.joined {
            self.handle.abort();
        }
    }
}
struct CaseChild {
    kind: ChildKind,
    owner: OwnedJoin<anyhow::Result<()>>,
}
struct CaseCustody(std::sync::Mutex<Vec<CaseChild>>);
impl CaseCustody {
    fn new() -> Self {
        Self(std::sync::Mutex::new(Vec::with_capacity(2)))
    }
    fn spawn<F>(&self, kind: ChildKind, future: F)
    where
        F: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let mut children = self.0.lock().unwrap_or_else(|error| error.into_inner());
        let owner = OwnedJoin {
            handle: tokio::spawn(future),
            joined: false,
        };
        children.push(CaseChild { kind, owner });
    }
    fn take(&self) -> Vec<CaseChild> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(|error| error.into_inner()))
    }
}

async fn association_observed(
    settings: RelaySettings,
    custody: &CaseCustody,
    probe: std::sync::Arc<AssociationProbe>,
) -> (TcpStream, UdpSocket, SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_peer = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (control, _) = listener.accept().await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    custody.spawn(ChildKind::Association, async move {
        run_udp_association_observed(
            UdpSessionControl::SocksControl(control),
            socket,
            &settings,
            &policy::RelaySessionProfile::default(),
            super::super::TunnelTransportFamily::MasqueDerived,
            "127.0.0.1".parse().unwrap(),
            Some(probe),
        )
        .await
    });
    let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    (control_peer, app, address)
}

#[derive(Clone, Copy)]
enum OriginalCase {
    CapAbsence,
    ExistingEcho,
    FailureAfterFirstEcho,
}

async fn observed_original_body(
    case: OriginalCase,
    custody: std::sync::Arc<CaseCustody>,
    probe: std::sync::Arc<AssociationProbe>,
) -> Fixture {
    probe.phase("fixture_start");
    let fixture = Fixture::start_with_custody(Some(&custody)).await;
    probe.phase("association_start");
    let (control, app, address) =
        association_observed(fixture.settings.clone(), &custody, probe.clone()).await;
    let mut targets = Vec::new();
    for index in 0..129u16 {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let marker = index.to_be_bytes();
        let destination = ConnectTarget {
            host: "127.0.0.1".into(),
            port: target.local_addr().unwrap().port(),
        };
        probe.expect_target(usize::from(index), destination.clone());
        let packet = socks5::encode_udp_packet(&destination, &marker).unwrap();
        probe.phase("original_udp_send");
        app.send_to(&packet, address).await.unwrap();
        probe.sent();
        if index == 0 {
            probe.phase("first_target_echo");
            echo_once(&target, &marker).await;
            let mut response = [0u8; 256];
            probe.phase("first_app_receipt");
            let (n, _) = app.recv_from(&mut response).await.unwrap();
            assert_eq!(
                socks5::parse_udp_packet(&response[..n]).unwrap().payload,
                marker
            );
            probe.delivered(0);
            if matches!(case, OriginalCase::FailureAfterFirstEcho) {
                probe.phase("controlled_failure_after_first_echo");
                panic!("controlled fixture body failure");
            }
        }
        targets.push((target, marker));
    }
    // Every original send remains in its original order. No pacing, packet
    // retry, second target payload, echo of the other 127 targets, or new clock.
    // The actual cap includes queued/opening targets; the other 127 egress
    // deliveries are outside this original cap/first-flow contract.
    probe.phase("actual_cap_refusal");
    probe.cap_refusal().await;
    probe.complete_validity();
    match case {
        OriginalCase::CapAbsence => {
            probe.phase("original_129th_absence_assertion");
            probe.original_absence_started();
            let mut absent = [0u8; 8];
            let absence = tokio::time::timeout(
                Duration::from_secs(10),
                targets[128].0.recv_from(&mut absent),
            )
            .await;
            probe.original_absence_result(&absence);
            assert!(absence.is_err());
        }
        OriginalCase::FailureAfterFirstEcho => {
            unreachable!("controlled fixture body must fail after its first authenticated echo");
        }
        OriginalCase::ExistingEcho => {
            let marker = b"post-cap";
            let first = ConnectTarget {
                host: "127.0.0.1".into(),
                port: targets[0].0.local_addr().unwrap().port(),
            };
            probe.phase("original_post_cap_send");
            app.send_to(&socks5::encode_udp_packet(&first, marker).unwrap(), address)
                .await
                .unwrap();
            probe.phase("original_post_cap_target_echo");
            echo_once(&targets[0].0, marker).await;
            let mut response = [0u8; 256];
            probe.phase("original_post_cap_app_assertion");
            let (n, _) = app.recv_from(&mut response).await.unwrap();
            assert_eq!(
                socks5::parse_udp_packet(&response[..n]).unwrap().payload,
                marker
            );
            probe.successful_post_cap_echo();
        }
    }
    probe.phase("original_control_drop");
    drop(control);
    // The exterior parent performs the original association await within the
    // same original 20-second cutoff and retains the original fixture lifetime.
    fixture
}

async fn observed_original_case(case: OriginalCase, original_failure: &'static str) {
    let end = tokio::time::Instant::now() + Duration::from_secs(20);
    let custody = std::sync::Arc::new(CaseCustody::new());
    let probe = std::sync::Arc::new(AssociationProbe::new());
    probe.original_case_deadline(end);
    let mut body = OwnedJoin {
        handle: tokio::spawn(observed_original_body(case, custody.clone(), probe.clone())),
        joined: false,
    };
    let body_result = tokio::time::timeout_at(end, &mut body.handle).await;
    probe.original_body_result(&body_result);
    body.joined = body_result.is_ok();
    let body_panicked = matches!(&body_result, Ok(Err(error)) if error.is_panic());
    let (body_success, _fixture) = match body_result {
        Ok(Ok(fixture)) => (true, Some(fixture)),
        _ => (false, None),
    };
    // An expired/panicked body cannot continue registering new children after
    // a confirmed join. Abort first; diagnostics never precede cancellation.
    let mut cleanup_end = None;
    if !body.joined {
        body.handle.abort();
        let cutoff = tokio::time::Instant::now() + Duration::from_millis(500);
        cleanup_end = Some(cutoff);
        body.joined = tokio::time::timeout_at(cutoff, &mut body.handle)
            .await
            .is_ok();
    }
    let mut children = custody.take();
    let mut association_success = false;
    if body_success {
        probe.phase("original_association_join");
        if let Some(child) = children
            .iter_mut()
            .find(|child| child.kind == ChildKind::Association)
        {
            let result = tokio::time::timeout_at(end, &mut child.owner.handle).await;
            probe.original_association_result(&result);
            child.owner.joined = result.is_ok();
            association_success = matches!(result, Ok(Ok(Ok(()))));
        }
    }
    let cleanup_end =
        cleanup_end.unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_millis(500));
    // After the body's confirmed exit its control socket is dropped. Prefer the
    // real association close -> JoinSet::shutdown path within this ONE cleanup
    // cutoff, so cancellation of the outer association is not called a join of
    // its descendant flows. No new case deadline or payload is introduced.
    for child in &mut children {
        if child.kind == ChildKind::Association && !child.owner.joined {
            child.owner.joined = tokio::time::timeout_at(cleanup_end, &mut child.owner.handle)
                .await
                .is_ok();
            if !child.owner.joined {
                child.owner.handle.abort();
            }
        }
    }
    // The original fixture server still uses abort for disposal. Its direct
    // handle is retained and joined; server-runtime descendants are outside this
    // receipt and require the independent process supervisor, including on PASS.
    for child in &children {
        if !child.owner.joined {
            child.owner.handle.abort();
        }
    }
    for child in &mut children {
        if !child.owner.joined {
            child.owner.joined = tokio::time::timeout_at(cleanup_end, &mut child.owner.handle)
                .await
                .is_ok();
        }
    }
    let joined = children.iter().filter(|child| child.owner.joined).count();
    let has_association = children
        .iter()
        .any(|child| child.kind == ChildKind::Association);
    let descendant_join = !has_association || probe.state().shutdown_joined;
    let cleanup = body.joined && joined == children.len() && descendant_join;
    probe.report(body.joined, joined, children.len(), cleanup);
    probe.report_original_results();
    assert!(
        cleanup,
        "INVALID: owned fixture cleanup not confirmed within separate 500ms allowance"
    );
    if matches!(case, OriginalCase::FailureAfterFirstEcho) {
        let state = probe.state();
        assert!(
            body_panicked
                && children.len() == 2
                && state.phase == "controlled_failure_after_first_echo"
                && state.sent == 1
                && state.slots[0].admissions == 1
                && state.slots[0].delivered
                && state.control_closed
                && state.shutdown_joined,
            "INVALID: controlled failure lacked its real first-echo and shutdown preconditions"
        );
        drop(state);
        // Only this exterior failure follows the confirmed cleanup assertion and
        // real control preconditions; the inner task panic has a different text.
        panic!("{original_failure}");
    }
    assert!(
        body_success && association_success && children.len() == 2,
        "{original_failure}"
    );
    probe.successful_original_shutdown();
}

async fn echo_once(target: &UdpSocket, expected: &[u8]) -> SocketAddr {
    let mut buf = [0u8; 256];
    let (n, peer) = target.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], expected);
    target.send_to(&buf[..n], peer).await.unwrap();
    peer
}

#[tokio::test]
async fn malformed_and_frag_do_not_latch_peer_then_two_targets_survive() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = Fixture::start().await;
        let (control, valid, address, owner) = association(fixture.settings.clone()).await;
        let invalid = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for bytes in [
            &b"\0\0"[..],
            &b"\0\0\x01\x01\x7f\0\0\x01\0\x35"[..],
            &b"\x01\0\0\x01\x7f\0\0\x01\0\x35"[..],
        ] {
            invalid.send_to(bytes, address).await.unwrap();
        }
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        for (target, marker) in [
            (&first, b"first".as_slice()),
            (&second, b"second".as_slice()),
        ] {
            let packet = socks5::encode_udp_packet(
                &ConnectTarget {
                    host: "127.0.0.1".into(),
                    port: target.local_addr().unwrap().port(),
                },
                marker,
            )
            .unwrap();
            valid.send_to(&packet, address).await.unwrap();
            echo_once(target, marker).await;
            let mut response = [0u8; 256];
            let (n, _) = valid.recv_from(&mut response).await.unwrap();
            assert_eq!(
                socks5::parse_udp_packet(&response[..n]).unwrap().payload,
                marker
            );
        }
        drop(control);
        owner.await.unwrap().unwrap();
    })
    .await
    .expect("bounded authenticated SOCKS association fixture");
}

#[tokio::test]
async fn live_target_cap_drops_only_129th_and_control_close_joins() {
    observed_original_case(
        OriginalCase::CapAbsence,
        "bounded 128-target authenticated association fixture",
    )
    .await;
}

#[tokio::test(flavor = "current_thread")]
async fn idle_target_is_retired_and_same_target_reopens() {
    let end = std::time::Instant::now() + Duration::from_secs(20);
    let custody = std::sync::Arc::new(CaseCustody::new());
    let association_probe = std::sync::Arc::new(AssociationProbe::new());
    let clock_probe = std::sync::Arc::new(IdleClockProbe::default());
    let hold = IDLE_CLOCK_AUTO_ADVANCE_HOLD.then(|| IdleClockHold::new(end));
    let body_custody = custody.clone();
    let body_association = association_probe.clone();
    let body_clock = clock_probe.clone();
    wall_bounded(
        async move {
            body_clock.phase("fixture_start");
            let fixture = Fixture::start_with_custody(Some(&body_custody)).await;
            body_clock.phase("association_start");
            let (control, app, address) = association_observed(
                fixture.settings.clone(),
                &body_custody,
                body_association.clone(),
            )
            .await;
            let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let destination = ConnectTarget {
                host: "127.0.0.1".into(),
                port: target.local_addr().unwrap().port(),
            };
            body_association.expect_target(0, destination.clone());
            let first = socks5::encode_udp_packet(&destination, b"before-idle").unwrap();
            body_clock.phase("first_original_send");
            app.send_to(&first, address).await.unwrap();
            let relay_peer = echo_once(&target, b"before-idle").await;
            let mut response = [0u8; 256];
            body_clock.phase("first_original_app_receipt");
            app.recv_from(&mut response).await.unwrap();
            body_clock.first(&body_association);

            let paused = PausedClock::new(body_clock.clone());
            let origin = paused.origin;
            body_clock.begin_manual_jump("manual_59_in_progress");
            tokio::time::advance(Duration::from_secs(59)).await;
            tokio::task::yield_now().await;
            body_clock.observe("manual_59_before_real_io", origin, Duration::from_secs(59));
            target
                .send_to(b"downlink-active", relay_peer)
                .await
                .unwrap();
            body_clock.phase("downlink_active_original_app_receipt");
            let (n, _) = app.recv_from(&mut response).await.unwrap();
            assert_eq!(
                socks5::parse_udp_packet(&response[..n]).unwrap().payload,
                b"downlink-active"
            );
            body_clock.observe("manual_59_after_real_io", origin, Duration::from_secs(59));
            body_clock.begin_manual_jump("manual_61_in_progress");
            tokio::time::advance(Duration::from_secs(2)).await;
            tokio::task::yield_now().await;
            body_clock.observe("manual_61_before_real_io", origin, Duration::from_secs(61));
            let still_live = socks5::encode_udp_packet(&destination, b"still-live").unwrap();
            app.send_to(&still_live, address).await.unwrap();
            body_clock.phase("still_live_original_target_echo");
            echo_once(&target, b"still-live").await;
            body_clock.phase("still_live_original_app_receipt");
            app.recv_from(&mut response).await.unwrap();
            body_clock.observe("manual_61_after_real_io", origin, Duration::from_secs(61));
            body_clock.preserved(&body_association);
            body_clock.begin_manual_jump("manual_122_in_progress");
            tokio::time::advance(Duration::from_secs(61)).await;
            tokio::task::yield_now().await;
            body_clock.observe(
                "manual_122_before_real_io",
                origin,
                Duration::from_secs(122),
            );
            let reopened = socks5::encode_udp_packet(&destination, b"reopened").unwrap();
            app.send_to(&reopened, address).await.unwrap();
            body_clock.phase("reopened_original_target_echo");
            echo_once(&target, b"reopened").await;
            body_clock.phase("reopened_original_app_receipt");
            app.recv_from(&mut response).await.unwrap();
            body_clock.observe("manual_122_after_real_io", origin, Duration::from_secs(122));
            body_clock.replaced(&body_association);
            drop(paused);

            drop(control);
            // Exterior owns the original association join, still within native END.
            fixture
        },
        custody,
        association_probe,
        clock_probe,
        end,
        hold,
    )
    .await;
}

#[tokio::test]
async fn failed_target_generation_does_not_close_healthy_flow_and_reopens() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let fixture = Fixture::start().await;
        let (control, app, address, owner) = association(fixture.settings.clone()).await;
        let healthy = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port_probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let failed_port = port_probe.local_addr().unwrap().port();
        drop(port_probe);
        let failed = ConnectTarget {
            host: "127.0.0.1".into(),
            port: failed_port,
        };
        let failed_packet = socks5::encode_udp_packet(&failed, b"will-fail").unwrap();
        app.send_to(&failed_packet, address).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;

        let healthy_target = ConnectTarget {
            host: "127.0.0.1".into(),
            port: healthy.local_addr().unwrap().port(),
        };
        for marker in [b"healthy-one".as_slice(), b"healthy-two".as_slice()] {
            let packet = socks5::encode_udp_packet(&healthy_target, marker).unwrap();
            app.send_to(&packet, address).await.unwrap();
            echo_once(&healthy, marker).await;
            let mut response = [0u8; 256];
            let (n, _) = app.recv_from(&mut response).await.unwrap();
            assert_eq!(
                socks5::parse_udp_packet(&response[..n]).unwrap().payload,
                marker
            );
        }

        let recovered = UdpSocket::bind(("127.0.0.1", failed_port)).await.unwrap();
        let retry = socks5::encode_udp_packet(&failed, b"recovered").unwrap();
        app.send_to(&retry, address).await.unwrap();
        echo_once(&recovered, b"recovered").await;
        let mut response = [0u8; 256];
        let (n, _) = app.recv_from(&mut response).await.unwrap();
        assert_eq!(
            socks5::parse_udp_packet(&response[..n]).unwrap().payload,
            b"recovered"
        );

        drop(control);
        owner.await.unwrap().unwrap();
    })
    .await
    .expect("bounded generation-isolated failure fixture");
}

#[tokio::test]
async fn stale_generation_downlink_cannot_refresh_or_escape_replacement() {
    let target = ConnectTarget {
        host: "127.0.0.1".into(),
        port: 443,
    };
    let (sender, _receiver) = mpsc::channel(1);
    let owner = tokio::spawn(std::future::pending::<()>());
    let mut tunnels = HashMap::new();
    let initial_activity = Instant::now();
    tunnels.insert(
        target.clone(),
        AssociateFlowEntry {
            generation: 2,
            sender,
            last_activity: initial_activity,
            abort: owner.abort_handle(),
        },
    );
    assert!(accept_associate_downlink(
        &mut tunnels,
        TaggedAssociateDownlink {
            generation: 1,
            packet: UdpPacket {
                target: target.clone(),
                payload: b"stale".to_vec(),
            },
        },
    )
    .is_none());
    assert_eq!(tunnels[&target].last_activity, initial_activity);
    assert_eq!(
        accept_associate_downlink(
            &mut tunnels,
            TaggedAssociateDownlink {
                generation: 2,
                packet: UdpPacket {
                    target: target.clone(),
                    payload: b"current".to_vec(),
                },
            },
        )
        .unwrap()
        .payload,
        b"current"
    );
    owner.abort();
    assert!(owner.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn full_flow_queue_drops_only_that_datagram_and_other_flow_progresses() {
    let (full_sender, mut full_receiver) = mpsc::channel(256);
    for index in 0..256u16 {
        full_sender.try_send(index.to_be_bytes().to_vec()).unwrap();
    }
    let full_owner = tokio::spawn(std::future::pending::<()>());
    let mut full = AssociateFlowEntry {
        generation: 1,
        sender: full_sender,
        last_activity: Instant::now(),
        abort: full_owner.abort_handle(),
    };
    assert!(matches!(
        queue_associate_payload(&mut full, b"dropped".to_vec()),
        AssociateQueueResult::Full
    ));
    for index in 0..256u16 {
        assert_eq!(full_receiver.recv().await.unwrap(), index.to_be_bytes());
    }

    let (other_sender, mut other_receiver) = mpsc::channel(1);
    let other_owner = tokio::spawn(std::future::pending::<()>());
    let mut other = AssociateFlowEntry {
        generation: 2,
        sender: other_sender,
        last_activity: Instant::now(),
        abort: other_owner.abort_handle(),
    };
    assert!(matches!(
        queue_associate_payload(&mut other, b"other-progress".to_vec()),
        AssociateQueueResult::Queued
    ));
    assert_eq!(other_receiver.recv().await.unwrap(), b"other-progress");
    full_owner.abort();
    other_owner.abort();
    assert!(full_owner.await.unwrap_err().is_cancelled());
    assert!(other_owner.await.unwrap_err().is_cancelled());
}

#[tokio::test]
async fn admitted_flow_still_echoes_after_129th_target_attempt() {
    observed_original_case(
        OriginalCase::ExistingEcho,
        "bounded post-cap established-flow fixture",
    )
    .await;
}

#[tokio::test]
#[should_panic(
    expected = "controlled failure after authenticated first echo and confirmed cleanup"
)]
async fn controlled_failure_after_first_authenticated_echo_keeps_parent_custody() {
    observed_original_case(
        OriginalCase::FailureAfterFirstEcho,
        "controlled failure after authenticated first echo and confirmed cleanup",
    )
    .await;
}
