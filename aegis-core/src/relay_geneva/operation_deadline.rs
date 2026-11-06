//! Shared synchronous operation limit. This carries a time bound, never authority.
//! Nested native helpers may shorten the original deadline but cannot reset it.
use std::{
    cell::Cell,
    io,
    marker::PhantomData,
    rc::Rc,
    time::{Duration, Instant},
};

thread_local! { static DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) }; }

// The scope restores thread-local state, so it must never move to another thread.
pub(crate) struct Scope {
    previous: Option<Instant>,
    _same_thread: PhantomData<Rc<()>>,
}
impl Scope {
    pub(crate) fn until(deadline: Instant) -> Self {
        let previous = DEADLINE.with(|slot| {
            let old = slot.get();
            slot.set(Some(old.map_or(deadline, |prior| prior.min(deadline))));
            old
        });
        Self {
            previous,
            _same_thread: PhantomData,
        }
    }
}
impl Drop for Scope {
    fn drop(&mut self) {
        DEADLINE.with(|slot| slot.set(self.previous));
    }
}

/// Limit one synchronous operation, including its inputs and final result.
/// This does not preempt filesystem I/O, grant a role, or cross an async/thread hop.
pub fn with_deadline<T>(
    deadline: Instant,
    action: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    let _scope = Scope::until(deadline);
    check()?;
    let result = action()?;
    check()?;
    Ok(result)
}

/// Refuse an expired inherited operation before advancing to another phase.
pub fn check() -> io::Result<()> {
    if DEADLINE.with(|slot| slot.get().is_none_or(|end| Instant::now() < end)) {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned operation total deadline",
        ))
    }
}

/// Clamp a helper's local bound to the original operation's remaining interval.
pub fn bounded(duration: Duration) -> Instant {
    let now = Instant::now();
    let local = now.checked_add(duration).unwrap_or(now);
    DEADLINE.with(|slot| slot.get().map_or(local, |parent| parent.min(local)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn expired_parent_never_enters_an_action_or_resets_in_a_fresh_helper() {
        let mut entered = false;
        assert_eq!(
            with_deadline(Instant::now(), || {
                entered = true;
                Ok(())
            })
            .unwrap_err()
            .kind(),
            io::ErrorKind::TimedOut
        );
        assert!(!entered);
        assert!(check().is_ok());
    }
    #[test]
    fn every_nested_helper_shares_the_original_bound() {
        let original = Instant::now() + Duration::from_secs(10);
        with_deadline(original, || {
            assert_eq!(bounded(Duration::from_secs(80)), original);
            with_deadline(Instant::now() + Duration::from_secs(90), || {
                assert_eq!(bounded(Duration::from_secs(30)), original);
                Ok(())
            })?;
            assert_eq!(bounded(Duration::from_secs(80)), original);
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn late_success_is_refused_and_the_previous_scope_is_restored() {
        let end = Instant::now() + Duration::from_millis(2);
        let error = with_deadline(end, || {
            while Instant::now() < end {
                std::hint::spin_loop();
            }
            Ok("late valid result")
        })
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(check().is_ok());
    }
    #[test]
    fn failure_and_unwind_restore_only_the_current_threads_scope() {
        let original = Instant::now() + Duration::from_secs(10);
        with_deadline(original, || {
            let error = with_deadline(Instant::now() + Duration::from_secs(5), || {
                Err::<(), _>(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "original failure",
                ))
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let _ = std::panic::catch_unwind(|| {
                let _scope = Scope::until(Instant::now());
                panic!("inert unwind");
            });
            assert_eq!(bounded(Duration::from_secs(80)), original);
            std::thread::spawn(|| assert!(check().is_ok()))
                .join()
                .unwrap();
            Ok(())
        })
        .unwrap();
    }
}
