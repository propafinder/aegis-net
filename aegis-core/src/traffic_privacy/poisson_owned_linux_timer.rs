//! Timer coalescing policy for a newly spawned, directly owned release thread.
//! Linux inherits timer slack across thread creation and exec; even a short
//! sleep request may otherwise acquire an unrelated caller's coalescing delay.
//! This does not change scheduling priority or promise a native wake deadline.
use std::io;

fn refused(kind: io::ErrorKind, name: &'static str) -> io::Error {
    io::Error::new(kind, super::Phase(name))
}

/// Called only by the release thread before readiness. Charge/check the
/// original work, cancellation and deadline budgets before both native calls.
/// Thread exit disposes of the policy; the caller's thread is never modified.
pub(super) fn initialize(before_native: &mut impl FnMut() -> io::Result<()>) -> io::Result<()> {
    before_native()?;
    // SAFETY: PR_SET_TIMERSLACK takes one unsigned-long scalar; no pointers.
    // A value of zero would restore the inherited default, so request 1 ns.
    let status = unsafe {
        libc::prctl(
            libc::PR_SET_TIMERSLACK,
            1 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if status != 0 {
        return Err(refused(
            io::Error::last_os_error().kind(),
            "linux_owned_timer_slack_set",
        ));
    }
    before_native()?;
    // SAFETY: PR_GET_TIMERSLACK returns the calling thread's scalar policy.
    let observed = unsafe {
        libc::prctl(
            libc::PR_GET_TIMERSLACK,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if observed != 1 {
        return Err(refused(
            if observed < 0 {
                io::Error::last_os_error().kind()
            } else {
                io::ErrorKind::InvalidData
            },
            "linux_owned_timer_slack_readback",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn slack() -> i32 {
        // SAFETY: scalar read of the current test thread's policy.
        unsafe {
            libc::prctl(
                libc::PR_GET_TIMERSLACK,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            )
        }
    }

    #[test]
    fn actual_owned_thread_replaces_inherited_coalescing_without_changing_caller() {
        let caller_slack = slack();
        assert!(caller_slack > 0);
        std::thread::spawn(|| {
            // SAFETY: alter only this disposable test thread's scalar policy.
            assert_eq!(
                unsafe {
                    libc::prctl(
                        libc::PR_SET_TIMERSLACK,
                        50_000_000 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                },
                0
            );
            let inherited = slack();
            std::thread::spawn(move || {
                assert_eq!(slack(), inherited);
                let mut charges = 0;
                initialize(&mut || {
                    charges += 1;
                    Ok(())
                })
                .unwrap();
                assert_eq!(charges, 2);
                assert_eq!(slack(), 1);
            })
            .join()
            .unwrap();
            assert_eq!(slack(), inherited);
        })
        .join()
        .unwrap();
        assert_eq!(slack(), caller_slack);
    }

    #[test]
    fn refused_original_budget_never_changes_timer_policy() {
        std::thread::spawn(|| {
            let before = slack();
            let error = initialize(&mut || Err(io::ErrorKind::TimedOut.into())).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(slack(), before);
        })
        .join()
        .unwrap();
    }
}
