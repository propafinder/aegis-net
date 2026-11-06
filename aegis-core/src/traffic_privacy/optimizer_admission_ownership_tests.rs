//! Real adaptive preparation ownership regressions in fresh processes.
//! Product admission remains global and unchanged; scoped probes only observe.
use super::adaptive_channel::{self, Action, AdaptiveSettings, PreparedChannel};
use super::optimizer_admission_test_support::{
    self as probe, PreparationProbe, Snapshot, SolverOutcome,
};
use std::{
    future::{poll_fn, Future},
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::{
    task::JoinHandle,
    time::{timeout_at, Instant},
};

// The product policy under test is four owners / 32 waiters. These fixtures do
// not reduce, replace, or bypass that production budget.
const HELD_OWNERS: usize = 4;
const PREFIX: &str = "traffic_privacy::optimizer_admission_ownership_tests::";

fn settings() -> AdaptiveSettings {
    AdaptiveSettings {
        objective: None,
        joint_counts: vec![vec![10, 0], vec![0, 10]],
        length_bin_upper: vec![16, 32],
        actions: vec![
            Action {
                padded_bytes: 16,
                delay_ms: 1,
            },
            Action {
                padded_bytes: 32,
                delay_ms: 1,
            },
        ],
        delay_cost_per_ms: 0,
        cost_budget: 32,
        optimizer_iterations: 1000,
        optimizer_gap_millibits: 1,
        optimizer_timeout_ms: 1000,
        buffer_bytes: 64,
        max_wire_bytes: 100_000,
        io_timeout_ms: 300,
        session_timeout_ms: 2000,
        max_queue_delay_ms: 30_000,
    }
}

fn valid_model(prepared: &PreparedChannel) {
    let expected = settings();
    assert_eq!(
        prepared.settings(),
        &expected,
        "INVALID: actual model/profile changed"
    );
    assert_eq!(prepared.descriptor(), expected.descriptor().unwrap());
    let certificate = prepared.certificate();
    assert!(certificate.iterations > 0 && certificate.iterations <= 1000);
    assert!(certificate.original_gap_bound_bits.is_finite());
    assert!(certificate.original_gap_bound_bits <= 0.001);
    assert!(certificate.maximum_information.is_none());
}

fn valid_completed_probe(snapshot: Snapshot, outcome: SolverOutcome) {
    assert_eq!(
        snapshot.task_created, 1,
        "INVALID: missing real task creation"
    );
    assert_eq!(
        snapshot.worker_entered, 1,
        "INVALID: missing real worker entry"
    );
    assert_eq!(
        snapshot.optimizer_entered, 1,
        "INVALID: actual optimizer not called once"
    );
    assert_eq!(
        snapshot.worker_exited, 1,
        "INVALID: worker scope not released"
    );
    assert!(
        !snapshot.gate_expired,
        "INVALID: fixture held work through its own cutoff"
    );
    assert!(snapshot.original_cutoff.is_some());
    assert_eq!(
        snapshot.outcome,
        Some(outcome),
        "INVALID: actual optimizer result differs"
    );
    assert_eq!(snapshot.directional_outcomes, [Some(outcome), None]);
}

struct Held {
    probe: Arc<PreparationProbe>,
    caller: Option<JoinHandle<io::Result<PreparedChannel>>>,
    original_fixture_cutoff: Instant,
    cancelled: bool,
}
impl Drop for Held {
    fn drop(&mut self) {
        self.probe.release();
        if let Some(caller) = &self.caller {
            caller.abort();
        }
    }
}
impl Held {
    async fn start() -> Self {
        let profile = settings();
        profile.validate().unwrap();
        let original_fixture_cutoff = Instant::now() + Duration::from_secs(2);
        let witness = PreparationProbe::held();
        let call_witness = witness.clone();
        let caller = tokio::spawn(probe::scope(
            call_witness,
            adaptive_channel::prepare(profile, original_fixture_cutoff),
        ));
        let held = Self {
            probe: witness,
            caller: Some(caller),
            original_fixture_cutoff,
            cancelled: false,
        };
        let snapshot = held
            .probe
            .wait_for(original_fixture_cutoff, |s| s.worker_entered == 1)
            .await;
        assert_eq!(snapshot.task_created, 1);
        assert_eq!(
            snapshot.optimizer_entered, 0,
            "INVALID: fixture gate did not hold real work"
        );
        assert_eq!(snapshot.worker_exited, 0);
        assert!(!snapshot.gate_expired);
        held
    }

    async fn cancel_caller(&mut self) {
        let caller = self.caller.as_mut().unwrap();
        caller.abort();
        let result = timeout_at(self.original_fixture_cutoff, caller)
            .await
            .expect("INVALID: owned caller cancellation was not observed");
        assert!(matches!(result, Err(error) if error.is_cancelled()));
        self.caller.take();
        self.cancelled = true;
        let snapshot = self.probe.snapshot();
        assert_eq!(snapshot.worker_entered, 1);
        assert_eq!(
            snapshot.worker_exited, 0,
            "INVALID: original real worker was not retained"
        );
        assert_eq!(snapshot.optimizer_entered, 0);
        assert!(!snapshot.gate_expired);
    }

    async fn finish(&mut self) {
        self.probe.release();
        if let Some(caller) = self.caller.as_mut() {
            let result = timeout_at(self.original_fixture_cutoff, caller)
                .await
                .expect("INVALID: original owned caller missed cleanup cutoff")
                .expect("INVALID: owned caller failed to join")
                .expect("INVALID: admitted real optimizer refused");
            self.caller.take();
            valid_model(&result);
        }
        let snapshot = self
            .probe
            .wait_for(self.original_fixture_cutoff, |s| s.worker_exited == 1)
            .await;
        valid_completed_probe(
            snapshot,
            if self.cancelled {
                SolverOutcome::Cancelled
            } else {
                SolverOutcome::Succeeded
            },
        );
    }
}

struct HeldSet(Vec<Held>);
impl HeldSet {
    async fn start() -> Self {
        let mut held = Self(Vec::with_capacity(HELD_OWNERS));
        for _ in 0..HELD_OWNERS {
            held.0.push(Held::start().await);
        }
        assert!(
            held.0.iter().all(|owner| {
                let snapshot = owner.probe.snapshot();
                snapshot.worker_entered == 1
                    && snapshot.worker_exited == 0
                    && !snapshot.gate_expired
            }),
            "INVALID: not four simultaneous original real worker owners"
        );
        held
    }

    async fn finish(&mut self) {
        // Release every bounded gate before any joins, including after errors.
        for owner in &self.0 {
            owner.probe.release();
        }
        for owner in &mut self.0 {
            owner.finish().await;
        }
    }
}

async fn bounded(work: impl Future<Output = ()>) {
    let started = std::time::Instant::now();
    tokio::select! {
        biased;
        () = work => (),
        () = async {
            loop {
                assert!(started.elapsed() < Duration::from_secs(20), "INVALID: independent real-wall fixture cutoff");
                tokio::task::yield_now().await;
            }
        } => unreachable!(),
    }
}

struct Marker {
    case: &'static str,
    directory: PathBuf,
}
impl Marker {
    fn enter(case: &'static str) -> Self {
        assert_eq!(
            std::env::var("AEGIS_OPTIMIZER_ADMISSION_CASE").unwrap(),
            case,
            "run this leaf through its fresh-process parent"
        );
        let directory =
            PathBuf::from(std::env::var_os("AEGIS_OPTIMIZER_ADMISSION_MARKER_DIR").unwrap());
        let marker = Self { case, directory };
        marker.write("entered", case);
        marker
    }
    fn write(&self, name: &str, contents: &str) {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.directory.join(name))
            .unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        file.sync_all().unwrap();
    }
    fn validity(&self, detail: &str) {
        self.write("validity", &format!("{}\n{detail}\n", self.case));
        println!("optimizer_fixture_validity: {} {detail}", self.case);
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual global-budget case; fresh-process parent owns this child"]
async fn task_creation_is_bounded_with_held_actual_optimizers_actual() {
    let marker = Marker::enter("task_creation_is_bounded_with_held_actual_optimizers_actual");
    bounded(async {
        let mut held = HeldSet::start().await;
        let fifth = PreparationProbe::released();
        let original_fifth_cutoff = Instant::now() + Duration::from_secs(2);
        let mut fifth_call = Box::pin(probe::scope(fifth.clone(),
            adaptive_channel::prepare(settings(), original_fifth_cutoff)));
        // Exactly one real prepare poll. The original synchronously creates a
        // fifth actual blocking job; the candidate waits before job creation.
        let first_poll = poll_fn(|cx| Poll::Ready(fifth_call.as_mut().poll(cx))).await;
        let fifth_created_before_release = fifth.snapshot().task_created;
        assert!(fifth_created_before_release <= 1, "INVALID: repeated prepare invocation");
        held.0[0].finish().await;
        let fifth_result = match first_poll {
            Poll::Ready(result) => result,
            Poll::Pending => timeout_at(original_fifth_cutoff, fifth_call.as_mut()).await
                .expect("INVALID: fifth owned prepare missed its original cutoff"),
        }.expect("INVALID: free-slot fifth actual optimizer refused");
        valid_model(&fifth_result);
        valid_completed_probe(fifth.snapshot(), SolverOutcome::Succeeded);
        held.finish().await;
        // Positive actual solve/cleanup witnesses precede the intended RED.
        marker.validity(&format!("held_real_solvers=4 fifth_real_solver=1 fifth_created_before_release={fifth_created_before_release} gates_expired=0 owners_joined=5"));
        assert_eq!(fifth_created_before_release, 0,
            "real fifth blocking job was created while four optimizer owners remained held");
    }).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual global-budget case; fresh-process parent owns this child"]
async fn cancelled_caller_retains_running_training_capacity_actual() {
    let marker = Marker::enter("cancelled_caller_retains_running_training_capacity_actual");
    bounded(async {
        let mut held = HeldSet::start().await;
        held.0[0].cancel_caller().await;
        let fifth = PreparationProbe::released();
        let original_fifth_cutoff = Instant::now() + Duration::from_millis(100);
        let fifth_result = probe::scope(fifth.clone(),
            adaptive_channel::prepare(settings(), original_fifth_cutoff)).await;
        let fifth_snapshot = fifth.snapshot();
        let fifth_created_while_cancelled_worker_held = fifth_snapshot.task_created;
        assert!(fifth_created_while_cancelled_worker_held <= 1, "INVALID: repeated extra invocation");
        if fifth_created_while_cancelled_worker_held == 1 {
            // Original source must genuinely finish its admitted extra solve.
            // A deadline/solver refusal here cannot be counted as the RED.
            let prepared = fifth_result.as_ref().expect("INVALID: baseline extra real solve refused");
            valid_model(prepared);
            valid_completed_probe(fifth_snapshot, SolverOutcome::Succeeded);
        } else {
            assert!(matches!(fifth_result, Err(ref error) if error.kind() == io::ErrorKind::TimedOut),
                "INVALID: capped fifth did not use its original expiry");
            assert_eq!(fifth_snapshot.worker_entered, 0);
            assert_eq!(fifth_snapshot.optimizer_entered, 0);
            assert_eq!(fifth_snapshot.worker_exited, 0);
        }
        let retained = held.0[0].probe.snapshot();
        assert_eq!(retained.worker_exited, 0, "INVALID: cancelled real worker already exited");
        assert_eq!(retained.optimizer_entered, 0);
        assert!(!retained.gate_expired);
        held.finish().await;
        let successor = PreparationProbe::released();
        let successor_end = Instant::now() + Duration::from_secs(2);
        let prepared = probe::scope(successor.clone(),
            adaptive_channel::prepare(settings(), successor_end)).await
            .expect("INVALID: capacity not recovered after actual worker scope exits");
        valid_model(&prepared);
        valid_completed_probe(successor.snapshot(), SolverOutcome::Succeeded);
        marker.validity(&format!("cancelled_caller_joined=1 original_worker_actual_outcome=Cancelled remaining_real_solvers=3 successor_real_solver=1 fifth_created_while_cancelled_worker_held={fifth_created_while_cancelled_worker_held} gates_expired=0"));
        assert_eq!(fifth_created_while_cancelled_worker_held, 0,
            "cancelling the awaiting caller admitted extra work while its real worker remained held");
    }).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual global-budget control; fresh-process parent owns this child"]
async fn original_profile_and_expired_cutoff_controls_actual() {
    let marker = Marker::enter("original_profile_and_expired_cutoff_controls_actual");
    bounded(async {
        let witness = PreparationProbe::released();
        let prepared = probe::scope(
            witness.clone(),
            adaptive_channel::prepare(settings(), Instant::now() + Duration::from_secs(2)),
        )
        .await
        .expect("INVALID: original admitted fixture did not solve");
        valid_model(&prepared);
        valid_completed_probe(witness.snapshot(), SolverOutcome::Succeeded);
        let expired = PreparationProbe::released();
        let refused = probe::scope(
            expired.clone(),
            adaptive_channel::prepare(settings(), Instant::now()),
        )
        .await;
        assert!(matches!(refused, Err(error) if error.kind() == io::ErrorKind::TimedOut));
        let snapshot = expired.snapshot();
        assert_eq!(snapshot.task_created, 0);
        assert_eq!(snapshot.worker_entered, 0);
        assert_eq!(snapshot.optimizer_entered, 0);
        assert_eq!(snapshot.worker_exited, 0);
        marker.validity("real_admitted_solver=1 expired_original_cutoff_jobs=0");
    })
    .await;
}

// Every case owns an isolated child with the real process-global production
// budget. Observation and cleanup have separate fixed real-wall cutoffs.
// Cleanup can remain UNCONFIRMED if the OS rejects kill or does not reap within
// the fixed cleanup budget; that is INVALID and never a no-dangling claim.
#[derive(Clone, Copy, Debug)]
struct Cleanup {
    pid: u32,
    reaped: bool,
    kill_failed: bool,
    wait_failed: bool,
}
impl Cleanup {
    fn confirmed(&self) -> bool {
        self.reaped && !self.kill_failed && !self.wait_failed
    }
}
struct OwnedChild {
    process: Option<std::process::Child>,
    pid: u32,
    cleanup: Option<Cleanup>,
}
impl OwnedChild {
    fn terminate_bounded(&mut self) -> Cleanup {
        // Never renew the cleanup budget or retry after an unconfirmed attempt.
        if let Some(report) = self.cleanup {
            return report;
        }
        let Some(child) = self.process.as_mut() else {
            return Cleanup {
                pid: self.pid,
                reaped: true,
                kill_failed: false,
                wait_failed: false,
            };
        };
        let cutoff = std::time::Instant::now() + Duration::from_millis(500);
        let mut report = Cleanup {
            pid: child.id(),
            reaped: false,
            kill_failed: false,
            wait_failed: false,
        };
        // Capture actual identity and attempt the one kill before any
        // potentially blocking/fallible diagnostics. Report at the caller only
        // after this bounded cleanup attempt, under the outer QA supervisor.
        report.kill_failed = child.kill().is_err();
        loop {
            match child.try_wait() {
                Ok(Some(_)) => {
                    // try_wait has observed/reaped this process. No unbounded
                    // Child::wait follows either this observation or kill.
                    report.reaped = true;
                    self.process.take();
                    self.cleanup = Some(report);
                    return report;
                }
                Ok(None) => {}
                Err(_) => {
                    report.wait_failed = true;
                    self.cleanup = Some(report);
                    return report;
                }
            }
            let now = std::time::Instant::now();
            if now >= cutoff {
                self.cleanup = Some(report);
                return report;
            }
            std::thread::sleep((cutoff - now).min(Duration::from_millis(1)));
        }
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.process.is_some() {
            let cleanup = self.terminate_bounded();
            // Diagnostics follow the one captured cleanup attempt. Ignore
            // stderr write errors rather than double-panicking during unwind;
            // an OS-blocked write is still bounded by the external supervisor.
            let _ = writeln!(
                io::stderr(),
                "optimizer_fixture_child_cleanup_result: pid={} {cleanup:?}",
                cleanup.pid
            );
            if !cleanup.confirmed() {
                let _ = writeln!(
                    io::stderr(),
                    "INVALID: child cleanup UNCONFIRMED: {cleanup:?}"
                );
            }
        }
    }
}

fn isolated(case: &'static str) {
    let mut scratch = Some(tempfile::tempdir().unwrap());
    let directory = scratch.as_ref().unwrap().path().to_owned();
    let spawn = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg(format!("{PREFIX}{case}"))
        .arg("--ignored")
        .arg("--test-threads=1")
        .arg("--nocapture")
        .env("AEGIS_OPTIMIZER_ADMISSION_CASE", case)
        .env("AEGIS_OPTIMIZER_ADMISSION_MARKER_DIR", &directory)
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .spawn();
    let spawned = match spawn {
        Ok(child) => child,
        Err(error) => {
            let retained = scratch.take().unwrap().keep();
            eprintln!(
                "optimizer_fixture_child_spawn_failed: case={case} pid=UNASSIGNED error={error}"
            );
            panic!("INVALID: child spawn failed case={case} pid=UNASSIGNED ({error}); markers retained at {}", retained.display());
        }
    };
    let pid = spawned.id();
    // Immediately own the real child before any diagnostic can fail or block.
    let mut child = OwnedChild {
        process: Some(spawned),
        pid,
        cleanup: None,
    };
    eprintln!("optimizer_fixture_child_spawned: case={case} pid={pid} parent_pid={} observation_budget_s=25", std::process::id());
    let observation_cutoff = std::time::Instant::now() + Duration::from_secs(25);
    let status = loop {
        match child.process.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => {
                child.process.take(); // Observed/reaped by try_wait; no wait call.
                eprintln!("optimizer_fixture_child_observed_reaped: case={case} pid={pid} status={status}");
                break status;
            }
            Ok(None) => {}
            Err(error) => {
                let cleanup = child.terminate_bounded();
                let retained = scratch.take().unwrap().keep();
                panic!("INVALID: child observation failed case={case} pid={pid} ({error}); cleanup={cleanup:?}; markers retained at {}", retained.display());
            }
        }
        let now = std::time::Instant::now();
        if now >= observation_cutoff {
            let cleanup = child.terminate_bounded();
            let retained = scratch.take().unwrap().keep();
            panic!("INVALID: owned child observation cutoff case={case} pid={pid}; cleanup={cleanup:?}; markers retained at {}", retained.display());
        }
        std::thread::sleep((observation_cutoff - now).min(Duration::from_millis(1)));
    };
    let entered = std::fs::read_to_string(directory.join("entered"));
    let validity = std::fs::read_to_string(directory.join("validity"));
    if !entered.as_ref().is_ok_and(|value| value == case)
        || !validity
            .as_ref()
            .is_ok_and(|value| value.starts_with(&format!("{case}\n")))
    {
        let retained = scratch.take().unwrap().keep();
        panic!("INVALID: isolated case {case} pid={pid} missing entry/validity witnesses: {status}; markers retained at {}", retained.display());
    }
    if !status.success() {
        let retained = scratch.take().unwrap().keep();
        // Marker proves the causal assertions came AFTER the actual numerical
        // positive controls and cleanup. Root still verifies the exact final
        // assertion/raw output; any unrelated panic is not an expected RED.
        panic!("SEMANTIC_RED_REQUIRES_RAW_ASSERTION_REVIEW: actual case {case} pid={pid}: {status}; markers retained at {}", retained.display());
    }
}

#[test]
fn optimizer_task_creation_bound_in_an_isolated_process() {
    isolated("task_creation_is_bounded_with_held_actual_optimizers_actual");
}

#[test]
fn optimizer_cancelled_caller_capacity_in_an_isolated_process() {
    isolated("cancelled_caller_retains_running_training_capacity_actual");
}

#[test]
fn optimizer_profile_cutoff_controls_in_an_isolated_process() {
    isolated("original_profile_and_expired_cutoff_controls_actual");
}

// Direct owned prepare futures create actual waiters when polled. No copy of
// the admission algorithm, budget override, or replacement optimizer is used.
const WAITING_INVOCATIONS: usize = 32;
type AdaptiveCall = std::pin::Pin<Box<dyn Future<Output = io::Result<PreparedChannel>> + Send>>;

struct PendingInvocation {
    probe: Arc<PreparationProbe>,
    call: Option<AdaptiveCall>,
    original_fixture_cutoff: Instant,
    created_on_first_poll: usize,
}
impl Drop for PendingInvocation {
    fn drop(&mut self) {
        // Drop the actual preparation owner before releasing a started gate,
        // so an observed original worker sees the real cancellation flag.
        self.call.take();
        self.probe.release();
    }
}
impl PendingInvocation {
    async fn start() -> Self {
        let original_fixture_cutoff = Instant::now() + Duration::from_secs(2);
        let witness = PreparationProbe::held();
        let mut call: AdaptiveCall = Box::pin(probe::scope(
            witness.clone(),
            adaptive_channel::prepare(settings(), original_fixture_cutoff),
        ));
        let first = poll_fn(|cx| Poll::Ready(call.as_mut().poll(cx))).await;
        assert!(
            matches!(first, Poll::Pending),
            "INVALID: one of the first 32 actual waiters refused or completed early"
        );
        let created_on_first_poll = witness.snapshot().task_created;
        assert!(
            created_on_first_poll <= 1,
            "INVALID: repeated pending prepare"
        );
        let pending = Self {
            probe: witness,
            call: Some(call),
            original_fixture_cutoff,
            created_on_first_poll,
        };
        if created_on_first_poll == 1 {
            let state = pending
                .probe
                .wait_for(original_fixture_cutoff, |s| s.worker_entered == 1)
                .await;
            assert_eq!(state.optimizer_entered, 0);
            assert_eq!(state.worker_exited, 0);
            assert!(
                !state.gate_expired,
                "INVALID: baseline pending worker gate expired"
            );
        }
        pending
    }

    async fn cancel(&mut self) {
        self.call.take();
        self.probe.release();
        if self.created_on_first_poll == 1 {
            let state = self
                .probe
                .wait_for(self.original_fixture_cutoff, |s| s.worker_exited == 1)
                .await;
            valid_completed_probe(state, SolverOutcome::Cancelled);
        } else {
            let state = self.probe.snapshot();
            assert_eq!(state.worker_entered, 0);
            assert_eq!(state.optimizer_entered, 0);
            assert_eq!(state.worker_exited, 0);
            assert!(state.original_cutoff.is_none());
        }
    }

    async fn finish(&mut self) {
        self.probe.release();
        let result = timeout_at(
            self.original_fixture_cutoff,
            self.call
                .as_mut()
                .expect("INVALID: cancelled call reused")
                .as_mut(),
        )
        .await
        .expect("INVALID: queued prepare missed its original cutoff")
        .expect("INVALID: actual queued optimizer refused");
        self.call.take();
        valid_model(&result);
        let state = self
            .probe
            .wait_for(self.original_fixture_cutoff, |s| s.worker_exited == 1)
            .await;
        valid_completed_probe(state, SolverOutcome::Succeeded);
    }
}

struct PendingSet(Vec<PendingInvocation>);
impl PendingSet {
    async fn start() -> Self {
        let mut set = Self(Vec::with_capacity(WAITING_INVOCATIONS));
        for _ in 0..WAITING_INVOCATIONS {
            set.0.push(PendingInvocation::start().await);
        }
        let created = set.0[0].created_on_first_poll;
        assert!(
            set.0.iter().all(|p| p.created_on_first_poll == created),
            "INVALID: inconsistent prefix admission/creation witnesses"
        );
        set
    }
    fn release_all(&self) {
        for pending in &self.0 {
            pending.probe.release();
        }
    }
    async fn finish(&mut self) {
        self.release_all();
        for pending in &mut self.0 {
            pending.finish().await;
        }
    }
}

fn valid_original_owners_held(held: &HeldSet) {
    assert!(
        held.0.iter().all(|owner| {
            let state = owner.probe.snapshot();
            state.worker_entered == 1
                && state.optimizer_entered == 0
                && state.worker_exited == 0
                && !state.gate_expired
        }),
        "INVALID: original four owners not held through contention observation"
    );
}

async fn saturated_extra() -> (usize, bool) {
    let witness = PreparationProbe::released();
    let original_cutoff = Instant::now() + Duration::from_secs(2);
    let result = probe::scope(
        witness.clone(),
        adaptive_channel::prepare(settings(), original_cutoff),
    )
    .await;
    let state = witness.snapshot();
    let created = state.task_created;
    assert!(created <= 1, "INVALID: extra call created repeatedly");
    let saturated = matches!(result, Err(ref error) if error.kind() == io::ErrorKind::WouldBlock);
    if created == 1 {
        valid_model(
            result
                .as_ref()
                .expect("INVALID: baseline overflow real solve refused"),
        );
        valid_completed_probe(state, SolverOutcome::Succeeded);
        assert!(!saturated);
    } else {
        assert!(
            saturated,
            "INVALID: overflow not refused by bounded waiter ownership"
        );
        assert_eq!(state.worker_entered, 0);
        assert_eq!(state.optimizer_entered, 0);
        assert_eq!(state.worker_exited, 0);
        assert!(state.original_cutoff.is_none());
    }
    (created, saturated)
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual global 4/32 budget; fresh-process parent owns this child"]
async fn thirty_two_waiters_refuse_thirty_third_before_task_creation_actual() {
    let marker =
        Marker::enter("thirty_two_waiters_refuse_thirty_third_before_task_creation_actual");
    bounded(async {
        let mut held = HeldSet::start().await;
        let mut pending = PendingSet::start().await;
        valid_original_owners_held(&held);
        let prefix_created = pending.0.iter().map(|p| p.created_on_first_poll).sum::<usize>();
        let (overflow_created, saturated) = saturated_extra().await;
        valid_original_owners_held(&held);
        pending.release_all();
        held.finish().await;
        pending.finish().await;
        marker.validity(&format!("real_owners=4 pending_invocations=32 prefix_created_before_release={prefix_created} overflow_created={overflow_created} overflow_WouldBlock={saturated} actual_prefix_solvers=36 gates_expired=0 caller_scopes_completed=36"));
        assert_eq!(prefix_created, 0,
            "real blocking jobs were created for the 32 bounded waiting preparations");
        assert!(saturated && overflow_created == 0,
            "the 33rd waiting preparation created a real optimizer job");
    }).await;
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual waiter cancellation; fresh-process parent owns this child"]
async fn cancelled_waiter_returns_one_bounded_admission_slot_actual() {
    let marker = Marker::enter("cancelled_waiter_returns_one_bounded_admission_slot_actual");
    bounded(async {
        let mut held = HeldSet::start().await;
        let mut pending = PendingSet::start().await;
        let mut cancelled = pending.0.remove(0);
        let cancelled_created = cancelled.created_on_first_poll;
        cancelled.cancel().await;
        valid_original_owners_held(&held);
        // With the four workers still held, this real replacement must enter
        // the single waiter slot just returned by dropping the real future.
        let replacement = PendingInvocation::start().await;
        let replacement_created = replacement.created_on_first_poll;
        pending.0.push(replacement);
        let (overflow_created, saturated) = saturated_extra().await;
        valid_original_owners_held(&held);
        pending.release_all();
        held.finish().await;
        pending.finish().await;
        marker.validity(&format!("real_owners=4 original_pending=32 cancelled_pending=1 cancelled_created={cancelled_created} replacement_pending=1 replacement_created={replacement_created} overflow_created={overflow_created} overflow_WouldBlock={saturated} successful_actual_solvers=36 gates_expired=0 caller_scopes_completed=36 cancelled_original_scope_verified=1"));
        assert_eq!(cancelled_created, 0,
            "waiting original caller had created a blocking job");
        assert_eq!(replacement_created, 0,
            "replacement caller created work while original workers were held");
        assert!(saturated && overflow_created == 0,
            "cancelled waiter did not restore exactly one bounded waiting slot");
    }).await;
}

fn liu_settings() -> super::liu_channel::LiuSettings {
    use super::liu_channel::{ClassMapping, LiuSettings, TrafficTransport};
    // Exact existing liu_channel_tests::settings model, cutoffs and limits.
    LiuSettings {
        class_weights: vec![1, 3],
        client_to_server_counts: vec![vec![3, 1], vec![1, 3]],
        server_to_client_counts: vec![vec![3, 1], vec![1, 3]],
        target_classes: vec![ClassMapping {
            host: "target.test".into(),
            port: 443,
            transport: TrafficTransport::Tcp,
            class: 0,
        }],
        unmatched_traffic_class: Some(1),
        policy_ack_class: 1,
        distortion_microunits: 125_000,
        optimizer_iterations: 2000,
        optimizer_gap_millibits: 1,
        optimizer_timeout_ms: 3000,
        buffer_bytes: 1024,
        wire_batch_bytes: 1024,
        max_wire_bytes: 100_000,
        io_timeout_ms: 300,
        session_timeout_ms: 3000,
        max_queue_delay_ms: 400_000,
    }
}

fn valid_liu_model(prepared: &super::liu_channel::PreparedChannel) {
    assert_eq!(
        prepared.settings(),
        &liu_settings(),
        "INVALID: Liu original profile changed"
    );
    for direction in 0..2 {
        let kernel = prepared.probabilities(direction).unwrap();
        assert_eq!(&kernel[2..4], &[0.0, 1.0]);
        assert_eq!(&kernel[4..8], &[1.0, 0.0, 0.0, 1.0]);
        assert!((kernel[0] - 1.0 / 3.0).abs() < 1e-14);
        assert!((kernel[1] - 2.0 / 3.0).abs() < 1e-14);
        let certificate = prepared.certificates()[direction];
        assert!(certificate.iterations > 0 && certificate.iterations <= 2000);
        assert!(certificate.original_gap_bound_bits.is_finite());
        assert!(certificate.original_gap_bound_bits <= 0.001);
        assert!(certificate.leakage_bits <= 1e-12);
        assert!(certificate.expected_cost <= 0.125 + 1e-12);
    }
}

fn valid_liu_probe(snapshot: Snapshot) {
    assert_eq!(snapshot.task_created, 1);
    assert_eq!(snapshot.worker_entered, 1);
    assert_eq!(
        snapshot.optimizer_entered, 2,
        "INVALID: both original directional solves not observed"
    );
    assert_eq!(snapshot.worker_exited, 1);
    assert!(
        !snapshot.gate_expired,
        "INVALID: Liu fixture gate passed original cutoff"
    );
    assert!(snapshot.original_cutoff.is_some());
    assert_eq!(
        snapshot.directional_outcomes,
        [
            Some(SolverOutcome::Succeeded),
            Some(SolverOutcome::Succeeded)
        ]
    );
}

type LiuCall =
    std::pin::Pin<Box<dyn Future<Output = io::Result<super::liu_channel::PreparedChannel>> + Send>>;
struct LiuInvocation {
    probe: Arc<PreparationProbe>,
    call: Option<LiuCall>,
}
impl Drop for LiuInvocation {
    fn drop(&mut self) {
        self.call.take();
        self.probe.release();
    }
}

#[tokio::test(flavor = "current_thread")]
#[ignore = "actual Liu shared owner; fresh-process parent owns this child"]
async fn liu_retains_shared_worker_across_both_unchanged_directional_solves_actual() {
    let marker =
        Marker::enter("liu_retains_shared_worker_across_both_unchanged_directional_solves_actual");
    bounded(async {
        let reference_probe = PreparationProbe::released();
        let reference = probe::scope(reference_probe.clone(),
            super::liu_channel::prepare(liu_settings(), Instant::now() + Duration::from_secs(3)))
            .await.expect("INVALID: actual original Liu reference solve refused");
        valid_liu_model(&reference);
        valid_liu_probe(reference_probe.snapshot());
        let mut held = HeldSet::start().await;
        let liu_probe = PreparationProbe::pause_after_first_solver();
        let original_liu_cutoff = Instant::now() + Duration::from_secs(3);
        let mut liu = LiuInvocation {
            probe: liu_probe.clone(),
            call: Some(Box::pin(probe::scope(liu_probe.clone(),
                super::liu_channel::prepare(liu_settings(), original_liu_cutoff)))),
        };
        let first = poll_fn(|cx| Poll::Ready(liu.call.as_mut().unwrap().as_mut().poll(cx))).await;
        assert!(matches!(first, Poll::Pending), "INVALID: Liu first poll did not suspend");
        let liu_created_while_four_adaptive_held = liu_probe.snapshot().task_created;
        assert!(liu_created_while_four_adaptive_held <= 1);
        held.0[0].finish().await;
        // Poll the actual caller concurrently with observing its real worker;
        // otherwise an admitted queued future would never create its job.
        let first_solver_state = tokio::select! {
            result = liu.call.as_mut().unwrap().as_mut() => {
                panic!("INVALID: Liu completed/refused before the between-direction gate: {}", result.is_ok());
            },
            state = liu_probe.wait_for(original_liu_cutoff, |s| s.first_solver_gate_entered) => state,
        };
        assert_eq!(first_solver_state.worker_entered, 1);
        assert_eq!(first_solver_state.optimizer_entered, 1);
        assert_eq!(first_solver_state.directional_outcomes,
            [Some(SolverOutcome::Succeeded), None]);
        assert_eq!(first_solver_state.worker_exited, 0);
        assert!(!first_solver_state.gate_expired);
        let extra_probe = PreparationProbe::released();
        let original_extra_cutoff = Instant::now() + Duration::from_millis(100);
        let extra_result = probe::scope(extra_probe.clone(),
            adaptive_channel::prepare(settings(), original_extra_cutoff)).await;
        let extra_state = extra_probe.snapshot();
        let extra_created_between_directions = extra_state.task_created;
        assert!(extra_created_between_directions <= 1);
        if extra_created_between_directions == 1 {
            valid_model(extra_result.as_ref().expect("INVALID: baseline extra adaptive real solver refused"));
            valid_completed_probe(extra_state, SolverOutcome::Succeeded);
        } else {
            assert!(matches!(extra_result, Err(ref error) if error.kind() == io::ErrorKind::TimedOut),
                "INVALID: shared-slot extra did not retain original cutoff");
            assert_eq!(extra_state.worker_entered, 0);
            assert_eq!(extra_state.optimizer_entered, 0);
            assert_eq!(extra_state.worker_exited, 0);
        }
        let held_liu = liu_probe.snapshot();
        assert_eq!(held_liu.optimizer_entered, 1);
        assert_eq!(held_liu.worker_exited, 0);
        assert!(!held_liu.gate_expired);
        assert!(held.0[1..].iter().all(|owner| {
            let state = owner.probe.snapshot();
            state.optimizer_entered == 0 && state.worker_exited == 0 && !state.gate_expired
        }), "INVALID: three other shared worker owners not retained");
        liu_probe.release();
        let prepared = timeout_at(original_liu_cutoff, liu.call.as_mut().unwrap().as_mut())
            .await.expect("INVALID: Liu original caller cutoff expired")
            .expect("INVALID: both unchanged Liu solves refused");
        liu.call.take();
        valid_liu_model(&prepared);
        valid_liu_probe(liu_probe.snapshot());
        assert_eq!(prepared.kernel_descriptor(), reference.kernel_descriptor(),
            "INVALID: actual directional IEEE kernels/certificates changed");
        for direction in 0..2 {
            let exact = |p: &super::liu_channel::PreparedChannel| {
                p.probabilities(direction).unwrap().iter().map(|x| x.to_bits()).collect::<Vec<_>>()
            };
            assert_eq!(exact(&prepared), exact(&reference));
        }
        held.finish().await;
        marker.validity(&format!("original_Liu_reference_actual_solvers=2 contender_actual_solvers=2 exact_directional_IEEE_equal=true adaptive_owners_completed=4 liu_created_while_four_adaptive_held={liu_created_while_four_adaptive_held} extra_created_between_directions={extra_created_between_directions} gates_expired=0"));
        assert_eq!((liu_created_while_four_adaptive_held, extra_created_between_directions), (0, 0),
            "Liu did not share/retain the same optimizer owner across both directional solves");
    }).await;
}

#[test]
fn optimizer_thirty_two_waiter_saturation_in_an_isolated_process() {
    isolated("thirty_two_waiters_refuse_thirty_third_before_task_creation_actual");
}

#[test]
fn optimizer_cancelled_waiter_slot_in_an_isolated_process() {
    isolated("cancelled_waiter_returns_one_bounded_admission_slot_actual");
}

#[test]
fn optimizer_liu_shared_directional_owner_in_an_isolated_process() {
    isolated("liu_retains_shared_worker_across_both_unchanged_directional_solves_actual");
}
