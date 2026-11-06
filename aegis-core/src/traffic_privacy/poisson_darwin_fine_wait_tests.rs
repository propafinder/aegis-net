//! Actual owned final-tail/coarse request selection and original guard tests.
//! Request planning and path selection do not prove native wake latency.
use super::*;

#[test]
fn actual_owned_planner_uses_original_coarse_request_before_final_tail() {
    let now = std::time::Instant::now();
    for remaining in [Duration::from_millis(1), Duration::from_millis(2)] {
        let point = now + remaining;
        let (wake, kind) = native_wait::plan_owned_bounded(now, point)
            .unwrap()
            .unwrap();
        assert!(wake > now && wake < point);
        let requested = wake.duration_since(now);
        println!("actual_owned_plan_requested_ns={}", requested.as_nanos());
        // This is a real request-duration assertion, not a renamed call counter.
        assert_eq!(
            requested,
            Duration::from_millis(1).min(remaining - Duration::from_micros(20)),
            "owned request must avoid repeated50us planning above final tail"
        );
        assert_eq!(kind, native_wait::WaitKind::Coarse);
    }
    for remaining in [Duration::from_micros(21), Duration::from_millis(3)] {
        let point = now + remaining;
        let (wake, _) = native_wait::plan_owned_bounded(now, point)
            .unwrap()
            .unwrap();
        assert!(wake > now);
        assert!(wake <= point - Duration::from_micros(20));
        assert!(wake.duration_since(now) <= Duration::from_millis(1));
    }
    assert_eq!(
        native_wait::plan_owned_bounded(now, now).unwrap(),
        Err(native_wait::Outcome::PointReached)
    );
    assert_eq!(
        native_wait::plan_owned_bounded(now, now + Duration::from_micros(20)).unwrap(),
        Err(native_wait::Outcome::ActiveTail)
    );
}

#[test]
fn actual_post_guard_owner_charges_only_original_final_twenty_us() {
    for remaining in [Duration::from_nanos(1), Duration::from_micros(20)] {
        let (mut worker, _app, _peer) = tests::fixture();
        let observed = std::time::Instant::now();
        let point = observed + remaining;
        let end = worker.end;
        let budget = worker.settings.precision_poll_budget;
        let work = worker.stats.native_work_steps;
        let spin = worker.stats.native_spin_steps;
        let mut entries = 0;
        worker.diagnostics.last_wait = Some(native_wait::WaitObservation {
            point,
            wake: observed,
            entered: observed,
            returned: Some(observed),
            status: Some(0),
            coarse: true,
            backend: "darwin_kevent64_critical_absolute",
        });
        worker.diagnostics.last_gather = Some((point, observed, (0, 0)));
        worker
            .absolute_wait_observed(point, observed, |owner, selected| {
                entries += 1;
                assert_eq!(selected, point);
                assert_eq!(owner.end, end);
                Ok(())
            })
            .unwrap();
        assert_eq!(
            entries, 0,
            "original active tail must not enter native wait"
        );
        assert_eq!(worker.stats.native_work_steps, work + 1);
        assert_eq!(worker.stats.native_spin_steps, spin + 1);
        assert_eq!(worker.diagnostics.wait_attempts, 1);
        assert!(worker.diagnostics.last_wait.is_none());
        assert!(worker.diagnostics.last_gather.is_none());
        assert_eq!(worker.diagnostics.waits_observed, 0);
        assert_eq!(worker.end, end);
        assert_eq!(worker.settings.precision_poll_budget, budget);
        assert_eq!(worker.stats.accepted_packets, 0);
        assert_eq!(worker.stats.sent_packets, 0);
    }
    for remaining in [
        Duration::from_micros(21),
        Duration::from_millis(1),
        Duration::from_millis(2),
    ] {
        let (mut worker, _app, _peer) = tests::fixture();
        let observed = std::time::Instant::now();
        let point = observed + remaining;
        let work = worker.stats.native_work_steps;
        let mut entries = 0;
        worker
            .absolute_wait_observed(point, observed, |_owner, selected| {
                entries += 1;
                assert_eq!(selected, point);
                Ok(())
            })
            .unwrap();
        assert_eq!(entries, 1);
        assert_eq!(worker.stats.native_work_steps, work);
        assert_eq!(worker.stats.native_spin_steps, 0);
    }
}

#[test]
fn actual_coarse_owner_preserves_native_boundary_and_original_point() {
    for remaining in [Duration::from_nanos(2_000_001), Duration::from_millis(3)] {
        let (mut worker, _app, _peer) = tests::fixture();
        let observed = std::time::Instant::now();
        let point = observed + remaining;
        let end = worker.end;
        let work = worker.stats.native_work_steps;
        let mut entries = 0;
        worker
            .absolute_wait_observed(point, observed, |owner, selected| {
                entries += 1;
                assert_eq!(selected, point);
                assert_eq!(owner.end, end);
                Ok(())
            })
            .unwrap();
        assert_eq!(entries, 1);
        assert_eq!(worker.stats.native_work_steps, work);
        assert_eq!(worker.stats.native_spin_steps, 0);
    }
}

#[test]
fn actual_reached_owner_keeps_existing_native_entry_without_active_charge() {
    for elapsed in [Duration::ZERO, Duration::from_micros(1)] {
        let (mut worker, _app, _peer) = tests::fixture();
        let observed = std::time::Instant::now();
        let point = observed - elapsed;
        let work = worker.stats.native_work_steps;
        let mut entries = 0;
        worker
            .absolute_wait_observed(point, observed, |_owner, selected| {
                entries += 1;
                assert_eq!(selected, point);
                Ok(())
            })
            .unwrap();
        assert_eq!(entries, 1);
        assert_eq!(worker.stats.native_work_steps, work);
        assert_eq!(worker.stats.native_spin_steps, 0);
    }
}

fn error_phase(error: &io::Error) -> &'static str {
    error.get_ref().unwrap().downcast_ref::<Phase>().unwrap().0
}

#[test]
fn actual_entry_cancel_or_expired_end_refuses_before_native_or_active_work() {
    for cancelled in [true, false] {
        let (mut worker, _app, _peer) = tests::fixture();
        if cancelled {
            worker.cancel.store(true, Ordering::Release);
        } else {
            worker.end = std::time::Instant::now();
        }
        let end = worker.end;
        let point = std::time::Instant::now() + Duration::from_millis(1);
        let mut entries = 0;
        let error = worker
            .absolute_wait_with(point, |_owner, _point| {
                entries += 1;
                Ok(())
            })
            .unwrap_err();
        assert_eq!(entries, 0);
        assert_eq!(worker.stats.native_spin_steps, 0);
        assert_eq!(worker.end, end);
        if cancelled {
            assert_eq!(error.kind(), io::ErrorKind::Interrupted);
            assert_eq!(error_phase(&error), "owned_release_cancelled");
        } else {
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(error_phase(&error), "owned_release_original_clock");
        }
    }
}

#[test]
fn actual_entry_precision_exhaustion_keeps_original_budget_and_refusal() {
    let (mut worker, _app, _peer) = tests::fixture();
    let end = worker.end;
    let budget = worker.settings.precision_poll_budget;
    worker.stats.precision_polls = budget as usize;
    let point = std::time::Instant::now() + Duration::from_millis(1);
    let mut entries = 0;
    let error = worker
        .absolute_wait_with(point, |_owner, _point| {
            entries += 1;
            Ok(())
        })
        .unwrap_err();
    assert_eq!(entries, 0);
    assert_eq!(error_phase(&error), "owned_work_budget");
    assert_eq!(worker.stats.precision_polls, budget as usize);
    assert_eq!(worker.settings.precision_poll_budget, budget);
    assert_eq!(worker.end, end);
    assert_eq!(worker.stats.native_spin_steps, 0);
}

#[test]
fn actual_fine_entry_work_exhaustion_cannot_borrow_or_enter_native_timer() {
    let (mut worker, _app, _peer) = tests::fixture();
    let end = worker.end;
    worker.stats.native_work_steps = MAX_WORK - 1;
    let point = std::time::Instant::now() + Duration::from_millis(1);
    // Actual production entry: its original guard consumes the last step.
    // Both versions must refuse before creating or entering a native timer.
    let error = worker.absolute_wait(point).unwrap_err();
    assert_eq!(error_phase(&error), "owned_work_budget");
    assert_eq!(worker.stats.native_work_steps, MAX_WORK);
    assert_eq!(worker.stats.native_spin_steps, 0);
    assert_eq!(worker.stats.native_absolute_coarse_wait_calls, 0);
    assert_eq!(worker.stats.native_absolute_fine_wait_calls, 0);
    assert!(worker.native_wait.is_none());
    assert_eq!(worker.end, end);
}

#[test]
fn actual_final_native_plan_cannot_reenter_fine_wait_after_coarse_entry() {
    let (mut worker, _app, _peer) = tests::fixture();
    let end = worker.end;
    let budget = worker.settings.precision_poll_budget;
    // Warm the real owned descriptor through the original reached-point path.
    // No timer is armed for this point, no private timer constructor bypass.
    worker
        .absolute_wait(std::time::Instant::now() - Duration::from_micros(1))
        .unwrap();
    assert!(worker.native_wait.is_some());
    let before = worker.stats.native_absolute_fine_wait_calls;
    let point = std::time::Instant::now() + Duration::from_millis(1);
    // Isolate a valid earlier coarse-entry observation. The selected native
    // implementation still reads its actual clock, plans and charges normally.
    let coarse_observed = point - Duration::from_millis(3);
    worker
        .absolute_wait_observed(point, coarse_observed, Worker::absolute_wait_native)
        .unwrap();
    let calls = worker.stats.native_absolute_fine_wait_calls - before;
    println!("actual_final_planner_fine_calls={calls}");
    assert_eq!(calls, 0, "owned final planner must not enter fine syscall");
    assert_eq!(worker.settings.precision_poll_budget, budget);
    assert_eq!(worker.end, end);
    assert_eq!(worker.stats.accepted_packets, 0);
    assert_eq!(worker.stats.sent_packets, 0);
}
