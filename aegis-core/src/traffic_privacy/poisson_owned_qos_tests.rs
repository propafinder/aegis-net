use super::*;
use std::cell::Cell;
struct Fake {
    calls: usize,
    reads: usize,
    writes: usize,
    prior: (u32, i32),
    requested: (u32, i32),
    fail_call: Option<usize>,
    mismatch: bool,
}
impl Fake {
    fn new(prior: (u32, i32)) -> Self {
        Self {
            calls: 0,
            reads: 0,
            writes: 0,
            prior,
            requested: prior,
            fail_call: None,
            mismatch: false,
        }
    }
    fn call(&mut self) -> io::Result<()> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_call == Some(call) {
            Err(failure(
                io::ErrorKind::PermissionDenied,
                "owned_qos_test_api",
            ))
        } else {
            Ok(())
        }
    }
}
impl Backend for Fake {
    type Thread = u8;
    fn current(&mut self) -> io::Result<u8> {
        self.call()?;
        Ok(1)
    }
    fn read(&mut self, thread: u8) -> io::Result<(u32, i32)> {
        assert_eq!(thread, 1);
        self.call()?;
        self.reads += 1;
        if self.reads == 1 {
            Ok(self.prior)
        } else if self.mismatch {
            Ok((0x11, 0))
        } else {
            Ok(self.requested)
        }
    }
    fn set_self(&mut self, class: u32, relative: i32) -> io::Result<()> {
        self.call()?;
        self.writes += 1;
        self.requested = (class, relative);
        Ok(())
    }
}
fn phase_of(error: &io::Error) -> &'static str {
    error
        .get_ref()
        .and_then(|e| e.downcast_ref::<Phase>())
        .unwrap()
        .0
}
#[test]
fn actual_helper_pre_call_clock_budget_cancel_refuse_without_api() {
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::Interrupted,
        io::ErrorKind::InvalidData,
    ] {
        let mut fake = Fake::new((0, 0));
        let error = configure(&mut fake, &mut |_| {
            Err(failure(kind, "owned_qos_test_cutoff"))
        })
        .err()
        .unwrap();
        assert_eq!(error.kind(), kind);
        assert_eq!(fake.calls, 0);
        assert_eq!(fake.writes, 0);
    }
}
#[test]
fn actual_helper_every_call_boundary_refuses_without_later_api() {
    for failed_boundary in 0usize..8 {
        let mut fake = Fake::new((0, 0));
        let count = Cell::new(0);
        let error = configure(&mut fake, &mut |_| {
            let boundary = count.get();
            count.set(boundary + 1);
            if boundary == failed_boundary {
                Err(failure(io::ErrorKind::TimedOut, "owned_qos_test_cutoff"))
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(count.get(), failed_boundary + 1);
        assert_eq!(fake.calls, failed_boundary.div_ceil(2));
    }
}
#[test]
fn actual_helper_late_api_completion_refuses_before_next_call() {
    let mut fake = Fake::new((0, 0));
    let count = Cell::new(0);
    let error = configure(&mut fake, &mut |boundary| {
        count.set(count.get() + 1);
        if matches!(boundary, Boundary::AfterNative) {
            Err(failure(
                io::ErrorKind::TimedOut,
                "owned_qos_test_late_return",
            ))
        } else {
            Ok(())
        }
    })
    .err()
    .unwrap();
    assert_eq!(phase_of(&error), "owned_qos_test_late_return");
    assert_eq!(count.get(), 2);
    assert_eq!(fake.calls, 1);
    assert_eq!(fake.writes, 0);
}
#[test]
fn actual_helper_api_failure_is_terminal_with_original_kind() {
    for failed_call in 0..4 {
        let mut fake = Fake::new((0, 0));
        fake.fail_call = Some(failed_call);
        let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(phase_of(&error), "owned_qos_test_api");
        assert_eq!(fake.calls, failed_call + 1);
    }
}
#[test]
fn actual_helper_unspecified_is_read_then_requested_and_verified() {
    let mut fake = Fake::new((0, 0));
    let charges = Cell::new(0);
    let observation = configure(&mut fake, &mut |boundary| {
        if matches!(boundary, Boundary::BeforeNative) {
            charges.set(charges.get() + 1);
        }
        Ok(())
    })
    .unwrap();
    assert_eq!(observation.prior_class, 0);
    assert_eq!(observation.prior_relative, 0);
    assert_eq!(observation.requested_class, USER_INITIATED);
    assert_eq!(observation.requested_relative, 0);
    assert!(observation.changed);
    assert_eq!(charges.get(), 4);
    assert_eq!(fake.reads, 2);
    assert_eq!(fake.writes, 1);
}
#[test]
fn actual_helper_higher_interactive_and_existing_initiated_are_preserved() {
    for prior in [(USER_INTERACTIVE, -3), (USER_INITIATED, 0)] {
        let mut fake = Fake::new(prior);
        let observation = configure(&mut fake, &mut |_| Ok(())).unwrap();
        assert!(!observation.changed);
        assert_eq!(fake.writes, 0);
        assert_eq!(fake.calls, 3);
        assert_eq!(
            (observation.requested_class, observation.requested_relative),
            prior
        );
    }
}
#[test]
fn actual_helper_readback_mismatch_and_invalid_prior_refuse() {
    let mut fake = Fake::new((0, 0));
    fake.mismatch = true;
    let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
    assert_eq!(phase_of(&error), "owned_qos_readback_mismatch");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    for prior in [(0xFF, 0), (0x15, 1), (0x15, -16)] {
        let mut fake = Fake::new(prior);
        let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
        assert_eq!(phase_of(&error), "owned_qos_prior_invalid");
        assert_eq!(fake.writes, 0);
        assert_eq!(fake.calls, 2);
    }
}
#[cfg(target_os = "macos")]
#[test]
fn native_return_codes_keep_kind_and_only_static_phase() {
    for (code, kind) in [
        (libc::EPERM, io::ErrorKind::PermissionDenied),
        (libc::EINVAL, io::ErrorKind::InvalidInput),
        (libc::EIO, io::ErrorKind::Other),
    ] {
        let error = returned(code, "owned_qos_set").unwrap_err();
        assert_eq!(error.kind(), kind);
        assert_eq!(phase_of(&error), "owned_qos_set");
        assert_eq!(error.to_string(), "owned_qos_set");
    }
}
#[cfg(target_os = "macos")]
#[test]
fn actual_short_owned_thread_requests_qos_and_joins_without_changing_parent() {
    use std::time::{Duration, Instant};
    let mut parent = Native;
    let parent_token = parent.current().unwrap();
    let before = parent.read(parent_token).unwrap();
    let end = Instant::now() + Duration::from_secs(2);
    let child = std::thread::Builder::new()
        .name("aegis-qos-owned-test".into())
        .spawn(move || {
            let mut charges = 0;
            let observation = initialize(&mut |boundary| {
                if Instant::now() >= end {
                    return Err(failure(
                        io::ErrorKind::TimedOut,
                        "owned_qos_test_original_clock",
                    ));
                }
                if matches!(boundary, Boundary::BeforeNative) {
                    charges += 1;
                }
                Ok(())
            })?;
            Ok::<_, io::Error>((observation, charges))
        })
        .unwrap();
    while !child.is_finished() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        Instant::now() < end,
        "original QoS test cutoff spent before terminal observation"
    );
    let finished = child.is_finished();
    assert!(
        Instant::now() < end,
        "terminal observation crossed original cutoff"
    );
    assert!(
        finished,
        "owned QoS child did not terminate within original test cutoff"
    );
    assert!(
        Instant::now() < end,
        "original cutoff spent before owned join"
    );
    let (observation, charges) = child.join().unwrap().unwrap();
    assert!(Instant::now() < end, "owned join crossed original cutoff");
    assert!(matches!(
        observation.requested_class,
        USER_INITIATED | USER_INTERACTIVE
    ));
    assert!((3..=4).contains(&charges));
    assert!(
        Instant::now() < end,
        "original cutoff spent before parent readback"
    );
    let after = parent.read(parent_token).unwrap();
    assert!(
        Instant::now() < end,
        "parent readback crossed original cutoff"
    );
    assert_eq!(after, before);
    assert!(
        Instant::now() < end,
        "final QoS acceptance crossed original cutoff"
    );
}
