use super::*;
struct Fake {
    calls: usize,
    class_reads: usize,
    priority_reads: usize,
    writes: usize,
    class: u32,
    relative: i32,
    fail_call: Option<usize>,
    priority_mismatch: bool,
    class_drift: bool,
}
impl Fake {
    fn new(class: u32, relative: i32) -> Self {
        Self {
            calls: 0,
            class_reads: 0,
            priority_reads: 0,
            writes: 0,
            class,
            relative,
            fail_call: None,
            priority_mismatch: false,
            class_drift: false,
        }
    }
    fn call(&mut self) -> io::Result<()> {
        let call = self.calls;
        self.calls += 1;
        if self.fail_call == Some(call) {
            Err(failure(
                io::ErrorKind::PermissionDenied,
                "owned_windows_priority_test_api",
            ))
        } else {
            Ok(())
        }
    }
}
impl Backend for Fake {
    type Thread = u8;
    type Process = u8;
    fn current_thread(&mut self) -> io::Result<u8> {
        self.call()?;
        Ok(1)
    }
    fn current_process(&mut self) -> io::Result<u8> {
        self.call()?;
        Ok(2)
    }
    fn class(&mut self, process: u8) -> io::Result<u32> {
        assert_eq!(process, 2);
        self.call()?;
        self.class_reads += 1;
        Ok(if self.class_reads > 1 && self.class_drift {
            0x8000
        } else {
            self.class
        })
    }
    fn priority(&mut self, thread: u8) -> io::Result<i32> {
        assert_eq!(thread, 1);
        self.call()?;
        self.priority_reads += 1;
        Ok(if self.priority_reads > 1 && self.priority_mismatch {
            0
        } else {
            self.relative
        })
    }
    fn set(&mut self, thread: u8, relative: i32) -> io::Result<()> {
        assert_eq!(thread, 1);
        assert_eq!(relative, 15);
        self.call()?;
        self.writes += 1;
        self.relative = relative;
        Ok(())
    }
}
fn phase(error: &io::Error) -> &'static str {
    error.get_ref().unwrap().downcast_ref::<Phase>().unwrap().0
}
#[test]
fn every_original_clock_cancel_work_boundary_stops_before_later_api() {
    for kind in [
        io::ErrorKind::TimedOut,
        io::ErrorKind::Interrupted,
        io::ErrorKind::InvalidData,
    ] {
        for stop in 0usize..14 {
            let mut fake = Fake::new(0x20, 0);
            let mut boundaries = 0;
            let error = configure(&mut fake, &mut |boundary| {
                assert_eq!(
                    matches!(boundary, Boundary::BeforeNative),
                    boundaries % 2 == 0
                );
                let current = boundaries;
                boundaries += 1;
                if current == stop {
                    Err(failure(kind, "original_guard"))
                } else {
                    Ok(())
                }
            })
            .err()
            .unwrap();
            assert_eq!(error.kind(), kind);
            assert_eq!(phase(&error), "original_guard");
            assert_eq!(fake.calls, stop.div_ceil(2));
            assert_eq!(boundaries, stop + 1);
        }
    }
}
#[test]
fn native_failure_is_terminal_and_postguard_takes_precedence() {
    for failed_call in 0..7 {
        let mut fake = Fake::new(0x20, 0);
        fake.fail_call = Some(failed_call);
        let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
        assert_eq!(phase(&error), "owned_windows_priority_test_api");
        assert_eq!(fake.calls, failed_call + 1);
        let mut fake = Fake::new(0x20, 0);
        fake.fail_call = Some(failed_call);
        let mut boundaries = 0;
        let error = configure(&mut fake, &mut |_| {
            let current = boundaries;
            boundaries += 1;
            if current == failed_call * 2 + 1 {
                Err(failure(io::ErrorKind::TimedOut, "original_guard"))
            } else {
                Ok(())
            }
        })
        .err()
        .unwrap();
        assert_eq!(phase(&error), "original_guard");
        assert_eq!(fake.calls, failed_call + 1);
    }
}
#[test]
fn forbidden_process_classes_stop_before_relative_query_or_mutation() {
    for class in [0, 0x80, 0x100, 0xffff_ffff] {
        let mut fake = Fake::new(class, 0);
        let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
        assert_eq!(phase(&error), "owned_windows_priority_class");
        assert_eq!((fake.calls, fake.priority_reads, fake.writes), (3, 0, 0));
    }
}
#[test]
fn invalid_relative_refuses_before_set() {
    for (class, relative, expected) in [
        (0x20, i32::MAX, "owned_windows_priority_relative"),
        (0x20, -3, "owned_windows_priority_relative"),
        (0x20, 3, "owned_windows_priority_relative"),
    ] {
        let mut fake = Fake::new(class, relative);
        let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
        assert_eq!(phase(&error), expected);
        assert_eq!((fake.calls, fake.writes), (4, 0));
    }
}
#[test]
fn every_admitted_class_requests_base_fifteen_and_preserves_existing_request() {
    for class in [0x40, 0x4000, 0x20, 0x8000] {
        for prior in [-15, -2, -1, 0, 1, 2, 15] {
            let mut fake = Fake::new(class, prior);
            let actual = configure(&mut fake, &mut |_| Ok(())).unwrap();
            assert_eq!(actual.process_class, class);
            assert_eq!(actual.prior_relative, prior);
            assert_eq!(actual.requested_relative, 15);
            assert_eq!(actual.requested_base, 15);
            assert_eq!(actual.changed, prior != 15);
            assert_eq!(fake.writes, usize::from(prior != 15));
            assert_eq!(fake.calls, 6 + usize::from(prior != 15));
        }
    }
}
#[test]
fn changed_readback_or_process_class_refuses_without_later_calls() {
    let mut fake = Fake::new(0x20, 0);
    fake.priority_mismatch = true;
    let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
    assert_eq!(phase(&error), "owned_windows_priority_readback");
    assert_eq!(fake.calls, 6);
    let mut fake = Fake::new(0x20, 0);
    fake.class_drift = true;
    let error = configure(&mut fake, &mut |_| Ok(())).err().unwrap();
    assert_eq!(phase(&error), "owned_windows_priority_class_changed");
    assert_eq!(fake.calls, 7);
}
#[cfg(windows)]
#[test]
fn actual_owned_windows_thread_readback_and_join_leave_parent_unchanged() {
    use std::time::{Duration, Instant};
    let end = Instant::now() + Duration::from_secs(2);
    // Parent only reads; all setters are confined to a newly owned child.
    let mut native = Native;
    let parent = native.current_thread().unwrap();
    let process = native.current_process().unwrap();
    let prior = native.priority(parent).unwrap();
    let class = native.class(process).unwrap();
    let child = std::thread::spawn(move || {
        initialize(&mut |_| {
            if Instant::now() >= end {
                Err(failure(io::ErrorKind::TimedOut, "original_test_end"))
            } else {
                Ok(())
            }
        })
    });
    while !child.is_finished() && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(Instant::now() < end);
    assert!(child.is_finished());
    let actual = child.join().unwrap().unwrap();
    assert!(Instant::now() < end);
    assert_eq!(actual.process_class, class);
    assert_eq!((actual.requested_relative, actual.requested_base), (15, 15));
    assert_eq!(native.priority(parent).unwrap(), prior);
    assert_eq!(native.class(process).unwrap(), class);
    assert!(Instant::now() < end);
}
