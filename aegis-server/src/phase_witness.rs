//! Explicitly owned, bounded local diagnostics. A snapshot is an aggregate of
//! this server instance, not a totally ordered trace or a wire-delivery proof.
//! No peer addresses, paths, headers, identities or payloads enter this type.
use std::sync::{
    atomic::{AtomicU64, AtomicU8, Ordering},
    Arc,
};
use std::time::Instant;
pub mod io_progress;
mod optimizer_startup;
pub use io_progress::{IoSnapshot, IoWitness};
pub use optimizer_startup::OptimizerStartupSnapshot;

#[derive(Clone, Copy)]
#[repr(usize)]
pub enum ServerPhase {
    TcpAccepted,
    OuterTlsAccepted,
    H2Established,
    H2RequestReceived,
    GrpcOpenReceived,
    GrpcOpenValidated,
    GrpcResponseHeadersQueued,
    TargetDialStarted,
    TcpSessionFinished,
}

const PHASES: [ServerPhase; 9] = [
    ServerPhase::TcpAccepted,
    ServerPhase::OuterTlsAccepted,
    ServerPhase::H2Established,
    ServerPhase::H2RequestReceived,
    ServerPhase::GrpcOpenReceived,
    ServerPhase::GrpcOpenValidated,
    ServerPhase::GrpcResponseHeadersQueued,
    ServerPhase::TargetDialStarted,
    ServerPhase::TcpSessionFinished,
];

impl ServerPhase {
    fn code(self) -> &'static str {
        match self {
            Self::TcpAccepted => "tcp_accepted",
            Self::OuterTlsAccepted => "outer_tls_accepted",
            Self::H2Established => "h2_established",
            Self::H2RequestReceived => "h2_request_received",
            Self::GrpcOpenReceived => "grpc_open_received",
            Self::GrpcOpenValidated => "grpc_open_validated",
            Self::GrpcResponseHeadersQueued => "grpc_response_headers_queued",
            Self::TargetDialStarted => "target_dial_started",
            Self::TcpSessionFinished => "tcp_session_finished",
        }
    }
}

struct Observation {
    count: AtomicU64,
    first_ms_plus_one: AtomicU64,
}
struct Witness {
    started: Instant,
    observations: [Observation; PHASES.len()],
    io: IoWitness,
    wire: IoWitness,
    accept: AcceptCounters,
    optimizer_startup: optimizer_startup::OptimizerStartupWitness,
}

#[derive(Default)]
struct AcceptCounters {
    polls: AtomicU64,
    pending: AtomicU64,
    requests: AtomicU64,
    eof: AtomicU64,
    errors: AtomicU64,
    error_kind: AtomicU8,
    cancelled: AtomicU64,
}
#[derive(Debug)]
pub struct AcceptSnapshot {
    pub polls: u64,
    pub pending: u64,
    pub requests: u64,
    pub eof: u64,
    pub errors: u64,
    pub last_error_kind: Option<&'static str>,
    /// Losing a select branch can cancel a pending accept future normally.
    /// This is not necessarily cancellation of the connection itself.
    pub cancelled: u64,
}
#[derive(Debug)]
pub struct TransportSnapshot {
    pub tls_application_io: IoSnapshot,
    pub tls_underlying_io: IoSnapshot,
    pub h2_accept: AcceptSnapshot,
}
fn bump(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
        Some(n.saturating_add(1))
    });
}
pub(crate) struct AcceptObservation {
    witness: ServerPhaseWitness,
    polled: bool,
    completed: bool,
}
impl AcceptObservation {
    pub(crate) fn poll_started(&mut self) {
        self.polled = true;
        bump(&self.witness.0.accept.polls);
    }
    pub(crate) fn result<T>(&mut self, result: &std::task::Poll<Option<Result<T, h2::Error>>>) {
        match result {
            std::task::Poll::Pending => bump(&self.witness.0.accept.pending),
            std::task::Poll::Ready(result) => {
                self.completed = true;
                match result {
                    Some(Ok(_)) => bump(&self.witness.0.accept.requests),
                    Some(Err(error)) => {
                        bump(&self.witness.0.accept.errors);
                        let kind = if error.is_io() {
                            1
                        } else if error.is_go_away() {
                            2
                        } else if error.is_reset() {
                            3
                        } else {
                            4
                        };
                        self.witness
                            .0
                            .accept
                            .error_kind
                            .store(kind, Ordering::Relaxed);
                    }
                    None => bump(&self.witness.0.accept.eof),
                }
            }
        }
    }
}
impl Drop for AcceptObservation {
    fn drop(&mut self) {
        if self.polled && !self.completed {
            bump(&self.witness.0.accept.cancelled);
        }
    }
}

#[derive(Clone)]
pub struct ServerPhaseWitness(Arc<Witness>);

#[derive(Debug)]
pub struct PhaseSnapshot {
    pub phase: &'static str,
    pub observations: u64,
    pub first_elapsed_ms: Option<u64>,
}

impl Default for ServerPhaseWitness {
    fn default() -> Self {
        Self(Arc::new(Witness {
            started: Instant::now(),
            observations: std::array::from_fn(|_| Observation {
                count: AtomicU64::new(0),
                first_ms_plus_one: AtomicU64::new(0),
            }),
            io: IoWitness::default(),
            wire: IoWitness::default(),
            accept: AcceptCounters::default(),
            optimizer_startup: optimizer_startup::OptimizerStartupWitness::default(),
        }))
    }
}

impl ServerPhaseWitness {
    /// Startup-only opt-in aggregate; no per-client observations or log sink.
    pub fn optimizer_startup_snapshot(&self) -> OptimizerStartupSnapshot {
        self.0.optimizer_startup.snapshot()
    }

    pub(crate) async fn observe_optimizer_startup<T, E>(
        witness: Option<&Self>,
        work: impl std::future::Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        optimizer_startup::observe(witness.map(|w| &w.0.optimizer_startup), work).await
    }
    pub(crate) fn observe_wire_io<S>(&self, io: S) -> io_progress::ObservedIo<S> {
        self.0.wire.observe(io)
    }
    pub(crate) fn observe_io<S>(&self, io: S) -> io_progress::ObservedIo<S> {
        self.0.io.observe(io)
    }
    pub(crate) fn observe_accept(&self) -> AcceptObservation {
        AcceptObservation {
            witness: self.clone(),
            polled: false,
            completed: false,
        }
    }
    /// Local TLS application-I/O and accept API counts, not encrypted socket
    /// bytes, peer ACKs, packet capture or application delivery. Fixed storage;
    /// this per-instance aggregate is not an atomic ordered snapshot.
    pub fn transport_snapshot(&self) -> TransportSnapshot {
        let a = &self.0.accept;
        TransportSnapshot {
            tls_application_io: self.0.io.snapshot(),
            tls_underlying_io: self.0.wire.snapshot(),
            h2_accept: AcceptSnapshot {
                polls: a.polls.load(Ordering::Relaxed),
                pending: a.pending.load(Ordering::Relaxed),
                requests: a.requests.load(Ordering::Relaxed),
                eof: a.eof.load(Ordering::Relaxed),
                errors: a.errors.load(Ordering::Relaxed),
                last_error_kind: match a.error_kind.load(Ordering::Relaxed) {
                    0 => None,
                    1 => Some("io"),
                    2 => Some("goaway"),
                    3 => Some("reset"),
                    _ => Some("other"),
                },
                cancelled: a.cancelled.load(Ordering::Relaxed),
            },
        }
    }
    pub(crate) fn note(&self, phase: ServerPhase) {
        let observation = &self.0.observations[phase as usize];
        let elapsed = self
            .0
            .started
            .elapsed()
            .as_millis()
            .min(u64::MAX as u128 - 1) as u64;
        let _ = observation.first_ms_plus_one.compare_exchange(
            0,
            elapsed + 1,
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
        let _ = observation
            .count
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                Some(n.saturating_add(1))
            });
    }

    /// Fixed nine-slot output. Concurrent observations can race this diagnostic
    /// snapshot; it must never authorize an operation or claim bytes delivered.
    pub fn snapshot(&self) -> [PhaseSnapshot; PHASES.len()] {
        PHASES.map(|phase| {
            let observation = &self.0.observations[phase as usize];
            PhaseSnapshot {
                phase: phase.code(),
                observations: observation.count.load(Ordering::Relaxed),
                first_elapsed_ms: observation
                    .first_ms_plus_one
                    .load(Ordering::Relaxed)
                    .checked_sub(1),
            }
        })
    }
}

pub(crate) fn note(witness: Option<&ServerPhaseWitness>, phase: ServerPhase) {
    if let Some(witness) = witness {
        witness.note(phase);
    }
}

pub(crate) struct SessionPhaseOwner(Option<ServerPhaseWitness>);
impl SessionPhaseOwner {
    pub(crate) fn new(witness: Option<&ServerPhaseWitness>) -> Self {
        Self(witness.cloned())
    }
}
impl Drop for SessionPhaseOwner {
    fn drop(&mut self) {
        note(self.0.as_ref(), ServerPhase::TcpSessionFinished);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_owned_witness_has_no_inferred_phases() {
        let witness = ServerPhaseWitness::default();
        let snapshot = witness.snapshot();
        assert_eq!(snapshot.len(), 9);
        assert!(snapshot
            .iter()
            .all(|p| p.observations == 0 && p.first_elapsed_ms.is_none()));
    }

    #[test]
    fn cloned_witness_keeps_first_phase_time_and_fixed_storage() {
        let witness = ServerPhaseWitness::default();
        witness.note(ServerPhase::H2Established);
        let first = witness.snapshot()[ServerPhase::H2Established as usize].first_elapsed_ms;
        let cloned = witness.clone();
        for _ in 0..1024 {
            cloned.note(ServerPhase::H2Established);
        }
        let snapshot = witness.snapshot();
        assert_eq!(snapshot.len(), 9);
        assert_eq!(
            snapshot[ServerPhase::H2Established as usize].observations,
            1025
        );
        assert_eq!(
            snapshot[ServerPhase::H2Established as usize].first_elapsed_ms,
            first
        );
        assert_eq!(
            snapshot[ServerPhase::GrpcOpenValidated as usize].observations,
            0
        );
        assert!(ServerPhaseWitness::default()
            .snapshot()
            .iter()
            .all(|p| p.observations == 0));
    }

    #[test]
    fn observations_saturate_and_disabled_witness_has_no_effect() {
        let witness = ServerPhaseWitness::default();
        witness.0.observations[ServerPhase::TcpAccepted as usize]
            .count
            .store(u64::MAX, Ordering::Relaxed);
        witness.note(ServerPhase::TcpAccepted);
        assert_eq!(
            witness.snapshot()[ServerPhase::TcpAccepted as usize].observations,
            u64::MAX
        );
        note(None, ServerPhase::TargetDialStarted);
        assert_eq!(
            witness.snapshot()[ServerPhase::TargetDialStarted as usize].observations,
            0
        );
    }
}
