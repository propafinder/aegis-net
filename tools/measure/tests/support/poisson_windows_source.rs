//! Test application source: the same finite nominal 2 ms grid as the paired
//! Linux fixture, with an exclusively owned high-resolution timer on Windows.
//! This changes fixture scheduling, not the channel or its original cutoffs.
use std::io;

const PERIOD_NS: u64 = 2_000_000;

// A late wake does not discard an application offer from the original grid.
// The caller records the actual dispatch and send-return times for each offer.
fn next_nominal(nominal: u64, dispatched: u64) -> io::Result<u64> {
    if !nominal.is_multiple_of(PERIOD_NS) || dispatched < nominal {
        return Err(io::ErrorKind::InvalidData.into());
    }
    nominal
        .checked_add(PERIOD_NS)
        .ok_or_else(|| io::ErrorKind::InvalidData.into())
}

#[cfg(windows)]
pub use native::spawn;

#[cfg(windows)]
mod native {
    use super::next_nominal;
    use crate::source_diagnostics::SourceWitness;
    use serde_json::Value;
    use std::{
        io,
        net::SocketAddr,
        os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
        time::{Duration, Instant},
    };
    use tokio::{net::UdpSocket, sync::oneshot, task::JoinHandle};
    use windows_sys::Win32::{
        Foundation::{WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            CreateWaitableTimerExW, SetWaitableTimerEx, WaitForSingleObject,
            CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, SYNCHRONIZATION_SYNCHRONIZE, TIMER_MODIFY_STATE,
        },
    };

    type Outcome = (u64, Option<io::ErrorKind>, bool, Value);
    const MAX_STEPS: usize = 250_000;
    const MAX_PACKETS: u64 = 8192;

    fn timer() -> io::Result<OwnedHandle> {
        // SAFETY: unnamed, exclusively owned auto-reset timer; no inherited
        // security descriptor, callback, shared object or system timer change.
        let handle = unsafe {
            CreateWaitableTimerExW(
                std::ptr::null(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_MODIFY_STATE | SYNCHRONIZATION_SYNCHRONIZE,
            )
        };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful creation transfers the unique live handle; Drop
        // closes it on every terminal path, including an armed timer.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }

    fn wait(timer: &OwnedHandle, point: Instant, end: Instant) -> io::Result<()> {
        let now = Instant::now();
        if now >= end {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let Some(delay) = point.checked_duration_since(now) else {
            return Ok(());
        };
        // Floor the relative100ns request. Any early return still needs the
        // original point check in the caller before an application send.
        let units = delay.as_nanos() / 100;
        if units == 0 {
            std::hint::spin_loop();
            return Ok(());
        }
        let due = -i64::try_from(units).map_err(|_| io::ErrorKind::InvalidData)?;
        // SAFETY: this live owned handle and stack pointer are valid for the
        // synchronous call; one-shot, zero APC/wakeup/coalescing allowance.
        if unsafe {
            SetWaitableTimerEx(
                timer.as_raw_handle(),
                &due,
                0,
                None,
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let now = Instant::now();
        if now >= end {
            return Err(io::ErrorKind::TimedOut.into());
        }
        if now >= point {
            return Ok(());
        }
        let remaining = point.duration_since(now).min(end.duration_since(now));
        let timeout = u32::try_from(remaining.as_nanos().div_ceil(1_000_000))
            .map_err(|_| io::ErrorKind::InvalidData)?;
        if timeout == 0 || timeout == u32::MAX {
            return Err(io::ErrorKind::InvalidData.into());
        }
        // SAFETY: bounded wait on only this timer. OS scheduling is not a
        // hard latency guarantee; original clocks are checked on return.
        match unsafe { WaitForSingleObject(timer.as_raw_handle(), timeout) } {
            WAIT_OBJECT_0 | WAIT_TIMEOUT => Ok(()),
            WAIT_FAILED => Err(io::Error::last_os_error()),
            _ => Err(io::ErrorKind::Other.into()),
        }
    }

    fn report(witness: &SourceWitness) -> Value {
        let mut r = witness.report();
        r["source_wait_backend"] = "windows_owned_high_resolution_grid".into();
        r
    }

    pub fn spawn(
        source: UdpSocket,
        destination: SocketAddr,
        start: tokio::time::Instant,
        covers_until: tokio::time::Instant,
        end: tokio::time::Instant,
        mut stop: oneshot::Receiver<()>,
    ) -> JoinHandle<Outcome> {
        // The blocking worker owns one timer and nonblocking application UDP
        // socket. No async worker/thread/process priority is modified. Aborting
        // spawn_blocking alone cannot stop it: receiver closure/stop and the
        // original end are checked every bounded loop; the caller joins it.
        tokio::task::spawn_blocking(move || {
            let mut witness = SourceWitness::default();
            let (start, covers_until, end) =
                (start.into_std(), covers_until.into_std(), end.into_std());
            let mut offered = 0;
            let result = (|| -> io::Result<bool> {
                let source = source.into_std()?; // Keeps its nonblocking mode.
                let timer = timer()?;
                let mut nominal = 0;
                for _ in 0..MAX_STEPS {
                    match stop.try_recv() {
                        Err(oneshot::error::TryRecvError::Empty) => {}
                        _ => return Err(io::ErrorKind::Interrupted.into()),
                    }
                    let now = Instant::now();
                    // Same stop > covers_until > original end precedence.
                    if now >= covers_until {
                        return Ok(true);
                    }
                    if now >= end {
                        return Err(io::ErrorKind::TimedOut.into());
                    }
                    let point = start
                        .checked_add(Duration::from_nanos(nominal))
                        .ok_or(io::ErrorKind::InvalidData)?;
                    if now < point {
                        wait(&timer, point.min(covers_until), end)?;
                        continue;
                    }
                    if offered >= MAX_PACKETS {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    let dispatched = u64::try_from(now.duration_since(start).as_nanos())
                        .map_err(|_| io::ErrorKind::InvalidData)?;
                    // Preserve every nominal offer after a late wake, as the
                    // paired Linux source does. A delayed send is observed at
                    // its actual dispatch/return time, not its grid point.
                    let next = next_nominal(nominal, dispatched)?;
                    witness.tick(nominal, dispatched);
                    match source.send_to(&offered.to_be_bytes(), destination)? {
                        8 => {}
                        _ => return Err(io::ErrorKind::WriteZero.into()),
                    }
                    let returned = u64::try_from(Instant::now().duration_since(start).as_nanos())
                        .map_err(|_| io::ErrorKind::InvalidData)?;
                    witness.sent(dispatched, returned);
                    offered += 1;
                    nominal = next;
                }
                Err(io::ErrorKind::TimedOut.into())
            })();
            let (kind, complete) = match result {
                Ok(complete) => (None, complete),
                Err(error) => (Some(error.kind()), false),
            };
            (offered, kind, complete, report(&witness))
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn owned_native_timer_checks_the_original_point_after_returns() {
            let timer = timer().unwrap();
            let start = Instant::now();
            let point = start + Duration::from_millis(2);
            let end = start + Duration::from_millis(200);
            for _ in 0..64 {
                let now = Instant::now();
                assert!(now < end);
                if now >= point {
                    return;
                }
                wait(&timer, point, end).unwrap();
            }
            panic!("original point was not observed within bounded work");
        }

        #[tokio::test]
        async fn closed_stop_joins_source_without_offering_any_packet() {
            let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let (stop, stopped) = oneshot::channel();
            drop(stop);
            let start = tokio::time::Instant::now();
            let end = start + Duration::from_secs(1);
            let result = tokio::time::timeout_at(
                end,
                spawn(
                    source,
                    sink.local_addr().unwrap(),
                    start,
                    start + Duration::from_millis(20),
                    end,
                    stopped,
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.0, 0);
            assert_eq!(result.1, Some(io::ErrorKind::Interrupted));
            assert!(!result.2);
            assert_eq!(result.3["successful_application_send_returns"], 0);
            assert_eq!(
                sink.try_recv_from(&mut [0; 8]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn original_grid_retains_each_late_offer() {
        assert_eq!(next_nominal(0, 0).unwrap(), PERIOD_NS);
        assert_eq!(next_nominal(0, 4_000_000).unwrap(), PERIOD_NS);
        assert_eq!(next_nominal(0, 5_000_000).unwrap(), PERIOD_NS);
        assert_eq!(next_nominal(0, 5_000_001).unwrap(), PERIOD_NS);
        assert_eq!(next_nominal(2_000_000, 7_000_000).unwrap(), 4_000_000);
        assert_eq!(next_nominal(2_000_000, 7_000_001).unwrap(), 4_000_000);
        assert_eq!(next_nominal(0, 15_779_200).unwrap(), PERIOD_NS);
        let mut nominal = 0;
        let mut retained = Vec::new();
        while nominal <= 15_779_200 {
            retained.push(nominal);
            nominal = next_nominal(nominal, 15_779_200).unwrap();
        }
        assert_eq!(
            retained,
            (0..8).map(|tick| tick * PERIOD_NS).collect::<Vec<_>>()
        );
    }

    #[test]
    fn malformed_grid_backwards_clock_and_overflow_refuse() {
        assert!(next_nominal(1, 2).is_err());
        assert!(next_nominal(PERIOD_NS, 0).is_err());
        let last = u64::MAX / PERIOD_NS * PERIOD_NS;
        assert!(next_nominal(last, last).is_err());
        assert_eq!(next_nominal(0, u64::MAX).unwrap(), PERIOD_NS);
    }
}
