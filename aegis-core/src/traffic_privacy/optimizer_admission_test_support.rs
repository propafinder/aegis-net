//! Scoped, per-invocation witnesses around the actual optimizer wrappers.
//! Test-only; no production admission override or global invocation counter.
use super::rate_distortion;
use std::{
    future::Future,
    sync::{Arc, Condvar, Mutex},
    time::Instant as StdInstant,
};
use tokio::{
    sync::watch,
    time::{timeout_at, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum SolverOutcome {
    Succeeded,
    Cancelled,
    Deadline,
    Refused,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Snapshot {
    pub task_created: usize,
    pub worker_entered: usize,
    pub optimizer_entered: usize,
    pub worker_exited: usize,
    pub gate_expired: bool,
    pub first_solver_gate_entered: bool,
    pub original_cutoff: Option<StdInstant>,
    pub outcome: Option<SolverOutcome>,
    // Exactly two bounded slots: adaptive uses slot zero, Liu uses both.
    pub directional_outcomes: [Option<SolverOutcome>; 2],
}

struct Gates {
    start_released: bool,
    after_first_released: bool,
}

pub(super) struct PreparationProbe {
    state: watch::Sender<Snapshot>,
    gates: Mutex<Gates>,
    gate: Condvar,
}

tokio::task_local! {
    static PREPARATION_PROBE: Arc<PreparationProbe>;
}

pub(super) fn capture() -> Option<Arc<PreparationProbe>> {
    PREPARATION_PROBE.try_with(Arc::clone).ok()
}

pub(super) async fn scope<T>(probe: Arc<PreparationProbe>, work: impl Future<Output = T>) -> T {
    PREPARATION_PROBE.scope(probe, work).await
}

impl PreparationProbe {
    pub fn held() -> Arc<Self> {
        Self::new(false, true)
    }

    pub fn released() -> Arc<Self> {
        Self::new(true, true)
    }

    pub fn pause_after_first_solver() -> Arc<Self> {
        Self::new(true, false)
    }

    fn new(start_released: bool, after_first_released: bool) -> Arc<Self> {
        let (state, _) = watch::channel(Snapshot::default());
        Arc::new(Self {
            state,
            gates: Mutex::new(Gates {
                start_released,
                after_first_released,
            }),
            gate: Condvar::new(),
        })
    }

    pub fn snapshot(&self) -> Snapshot {
        *self.state.borrow()
    }

    pub fn task_created(&self, original_cutoff: StdInstant) {
        self.state.send_modify(|state| {
            state.task_created += 1;
            state.original_cutoff = Some(original_cutoff);
        });
    }

    fn wait_gate(&self, after_first: bool, original_cutoff: StdInstant) {
        let mut gates = self.gates.lock().unwrap_or_else(|error| error.into_inner());
        while !(if after_first {
            gates.after_first_released
        } else {
            gates.start_released
        }) {
            let now = StdInstant::now();
            if now >= original_cutoff {
                self.state.send_modify(|state| state.gate_expired = true);
                break;
            }
            let (next, _) = self
                .gate
                .wait_timeout(gates, original_cutoff.duration_since(now))
                .unwrap_or_else(|error| error.into_inner());
            gates = next;
        }
    }

    pub fn enter_worker(self: Arc<Self>, original_cutoff: StdInstant) -> WorkerLifetime {
        // Construct Drop witness before entering a bounded blocking gate.
        let lifetime = WorkerLifetime(self.clone());
        self.state.send_modify(|state| state.worker_entered += 1);
        self.wait_gate(false, original_cutoff);
        lifetime
    }

    pub fn optimizer_entered(&self) {
        self.state.send_modify(|state| state.optimizer_entered += 1);
    }

    pub fn optimizer_returned(
        &self,
        result: &Result<rate_distortion::Channel, rate_distortion::Error>,
        original_cutoff: StdInstant,
    ) {
        let outcome = match result {
            Ok(_) => SolverOutcome::Succeeded,
            Err(rate_distortion::Error::Cancelled) => SolverOutcome::Cancelled,
            Err(rate_distortion::Error::Deadline) => SolverOutcome::Deadline,
            Err(_) => SolverOutcome::Refused,
        };
        let mut ordinal = 0;
        self.state.send_modify(|state| {
            ordinal = state.optimizer_entered;
            assert!(
                (1..=2).contains(&ordinal),
                "INVALID: scoped optimizer ordinal outside bounded witness"
            );
            state.directional_outcomes[ordinal - 1] = Some(outcome);
            state.outcome = Some(outcome);
        });
        let pause = ordinal == 1
            && !self
                .gates
                .lock()
                .unwrap_or_else(|error| error.into_inner())
                .after_first_released;
        if pause {
            self.state
                .send_modify(|state| state.first_solver_gate_entered = true);
            // Same captured product cutoff; no new between-direction deadline.
            self.wait_gate(true, original_cutoff);
        }
    }

    pub fn release(&self) {
        let mut gates = self.gates.lock().unwrap_or_else(|error| error.into_inner());
        gates.start_released = true;
        gates.after_first_released = true;
        drop(gates);
        self.gate.notify_all();
    }

    pub async fn wait_for(
        &self,
        original_fixture_cutoff: Instant,
        predicate: impl Fn(Snapshot) -> bool,
    ) -> Snapshot {
        let mut state = self.state.subscribe();
        timeout_at(original_fixture_cutoff, async {
            loop {
                let snapshot = *state.borrow_and_update();
                if predicate(snapshot) {
                    return snapshot;
                }
                state
                    .changed()
                    .await
                    .expect("fixture keeps its scoped probe owned");
            }
        })
        .await
        .expect("INVALID: missed scoped validity witness before original fixture cutoff")
    }
}

// Declared before the candidate permit binding. The expensive closure scope
// exits after the later permit drops; this does not witness OS thread death.
pub(super) struct WorkerLifetime(Arc<PreparationProbe>);
impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        self.0.state.send_modify(|state| state.worker_exited += 1);
    }
}
