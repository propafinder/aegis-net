//! Bounded absolute wait for an explicitly owned native release thread.
//! Preserve original point, <=1ms coarse / <=50us fine requests, final20us active guard.
use std::{
    io,
    time::{Duration, Instant},
};

const ACTIVE_TAIL: Duration = Duration::from_micros(20);
const FINE_CAP: Duration = Duration::from_micros(50);
const FINE_WINDOW: Duration = Duration::from_millis(2);
const COARSE_CAP: Duration = Duration::from_millis(1);

#[cfg(target_os = "macos")]
pub(super) fn darwin_active_tail(now: Instant, point: Instant) -> bool {
    now < point && point.duration_since(now) <= ACTIVE_TAIL
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(target_os = "macos")]
pub(super) enum Charge {
    InstantClockRead,
    MachClockRead,
    TimebaseRead,
    TimerCreate,
    AbsoluteCoarseWait,
    AbsoluteFineWait,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Outcome {
    PointReached,
    OutsideFineWindow,
    ActiveTail,
    #[cfg(target_os = "macos")]
    AbsoluteWaitReturned,
    #[cfg(windows)]
    WindowsWaitReturned,
}

fn phase(kind: io::ErrorKind, name: &'static str) -> io::Error {
    io::Error::new(kind, super::Phase(name))
}

/// Earliest conservative mapping from BEFORE-Instant raw anchor. Floor the
/// offset and reserve one raw tick; never reinterpret opaque Instant layout.
#[cfg(any(target_os = "macos", test))]
fn map_early(anchor: u64, delta_ns: u128, numer: u32, denom: u32) -> io::Result<u64> {
    if numer == 0 || denom == 0 {
        return Err(phase(io::ErrorKind::InvalidData, "darwin_timebase"));
    }
    let ticks = delta_ns
        .checked_mul(u128::from(denom))
        .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_timebase_overflow"))?
        / u128::from(numer);
    let early_ticks = ticks.saturating_sub(1);
    let early_ticks = u64::try_from(early_ticks)
        .map_err(|_| phase(io::ErrorKind::InvalidData, "darwin_timebase_overflow"))?;
    anchor
        .checked_add(early_ticks)
        .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_timebase_overflow"))
}

fn plan(now: Instant, point: Instant) -> io::Result<Result<Instant, Outcome>> {
    if now >= point {
        return Ok(Err(Outcome::PointReached));
    }
    let remaining = point.duration_since(now);
    if remaining > FINE_WINDOW {
        return Ok(Err(Outcome::OutsideFineWindow));
    }
    if remaining <= ACTIVE_TAIL {
        return Ok(Err(Outcome::ActiveTail));
    }
    let tail = point
        .checked_sub(ACTIVE_TAIL)
        .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_wait_clock"))?;
    let cap = now
        .checked_add(FINE_CAP)
        .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_wait_clock"))?;
    Ok(Ok(tail.min(cap)))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WaitKind {
    Coarse,
    Fine,
}

/// Preserve the old >2ms coarse region and <=1ms request, but map its wake
/// through the SAME raw/Instant anchor as the fine phase. No relative restart.
fn plan_bounded(now: Instant, point: Instant) -> io::Result<Result<(Instant, WaitKind), Outcome>> {
    if now >= point {
        return Ok(Err(Outcome::PointReached));
    }
    if point.duration_since(now) > FINE_WINDOW {
        let guard = point
            .checked_sub(FINE_WINDOW)
            .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_wait_clock"))?;
        let cap = now
            .checked_add(COARSE_CAP)
            .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_wait_clock"))?;
        return Ok(Ok((guard.min(cap), WaitKind::Coarse)));
    }
    Ok(plan(now, point)?.map(|wake| (wake, WaitKind::Fine)))
}

/// The installed owned thread uses the existing <=1ms absolute request cap
/// until the original final20us active tail. Public points are never shifted.
/// Short remaining intervals can still request <=50us on the same native
/// backend; this selection is not an OS latency or timer-cause guarantee.
#[cfg(target_os = "macos")]
pub(super) fn plan_owned_bounded(
    now: Instant,
    point: Instant,
) -> io::Result<Result<(Instant, WaitKind), Outcome>> {
    if now >= point {
        return Ok(Err(Outcome::PointReached));
    }
    if point.duration_since(now) <= ACTIVE_TAIL {
        return Ok(Err(Outcome::ActiveTail));
    }
    let tail = point
        .checked_sub(ACTIVE_TAIL)
        .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_wait_clock"))?;
    let cap = now
        .checked_add(COARSE_CAP)
        .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_wait_clock"))?;
    Ok(Ok((tail.min(cap), WaitKind::Coarse)))
}

/// ONLY the already-owned native release thread may call this blocking waiter.
/// No cancellation/reap/realtime claim: caller observes original clock and
/// cancellation after return, retaining actual joined-terminal evidence.
#[cfg(target_os = "macos")]
pub(super) struct DarwinAbsoluteWait {
    #[cfg(target_os = "macos")]
    pub(super) last_observation: Option<WaitObservation>,
    mach_before_instant: u64,
    instant_anchor: Instant,
    numer: u32,
    denom: u32,
    timer_queue: std::os::fd::OwnedFd,
}

// Private owned wait witness. Absolute instants are never formatted.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
pub(super) struct WaitObservation {
    pub(super) point: Instant,
    pub(super) wake: Instant,
    pub(super) entered: Instant,
    pub(super) returned: Option<Instant>,
    #[cfg(test)]
    pub(super) status: Option<i32>,
    pub(super) coarse: bool,
    #[cfg(test)]
    pub(super) backend: &'static str,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MachTimebase {
    numer: u32,
    denom: u32,
}
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebase) -> i32;
}

#[cfg(target_os = "macos")]
impl DarwinAbsoluteWait {
    pub(super) fn new(mut charge: impl FnMut(Charge) -> io::Result<()>) -> io::Result<Self> {
        let mut tb = MachTimebase { numer: 0, denom: 0 };
        charge(Charge::TimebaseRead)?;
        // SAFETY: correctly aligned writable C-layout output, valid for this call.
        let status = unsafe { mach_timebase_info(&mut tb) };
        if status != 0 || tb.numer == 0 || tb.denom == 0 {
            return Err(phase(io::ErrorKind::InvalidData, "darwin_timebase"));
        }
        charge(Charge::MachClockRead)?;
        // SAFETY: clock read has no arguments or ownership requirements.
        let mach_before_instant = unsafe { mach_absolute_time() };
        charge(Charge::InstantClockRead)?;
        let instant_anchor = Instant::now();
        charge(Charge::TimerCreate)?;
        // SAFETY: kqueue creates a new caller-owned descriptor, no callbacks.
        let fd = unsafe { libc::kqueue() };
        if fd < 0 {
            return Err(phase(
                io::Error::last_os_error().kind(),
                "darwin_timer_create",
            ));
        }
        use std::os::fd::FromRawFd;
        // SAFETY: fd is freshly returned and transferred exactly once.
        let timer_queue = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
        Ok(Self {
            #[cfg(target_os = "macos")]
            last_observation: None,
            mach_before_instant,
            instant_anchor,
            numer: tb.numer,
            denom: tb.denom,
            timer_queue,
        })
    }

    // Retain the original standalone native-wait contract for its existing
    // direct tests. Installed release owners use the explicit owned policy.
    #[cfg(test)]
    pub(super) fn wait_bounded(
        &mut self,
        point: Instant,
        charge: impl FnMut(Charge) -> io::Result<()>,
    ) -> io::Result<Outcome> {
        self.wait_with_policy(point, false, charge)
    }

    pub(super) fn wait_owned_bounded(
        &mut self,
        point: Instant,
        charge: impl FnMut(Charge) -> io::Result<()>,
    ) -> io::Result<Outcome> {
        self.wait_with_policy(point, true, charge)
    }

    fn wait_with_policy(
        &mut self,
        point: Instant,
        owned_coarse_tail: bool,
        mut charge: impl FnMut(Charge) -> io::Result<()>,
    ) -> io::Result<Outcome> {
        #[cfg(target_os = "macos")]
        {
            self.last_observation = None;
        }
        charge(Charge::InstantClockRead)?;
        let now = Instant::now();
        let planned = if owned_coarse_tail {
            plan_owned_bounded(now, point)?
        } else {
            plan_bounded(now, point)?
        };
        let (wake, kind) = match planned {
            Ok(wake) => wake,
            Err(outcome) => return Ok(outcome),
        };
        let offset = wake
            .checked_duration_since(self.instant_anchor)
            .ok_or_else(|| phase(io::ErrorKind::InvalidData, "darwin_anchor_order"))?;
        let raw = map_early(
            self.mach_before_instant,
            offset.as_nanos(),
            self.numer,
            self.denom,
        )?;
        let (request, timeout) = critical_timer_request(raw, wake.duration_since(now))?;
        // Charge every explicit syscall BEFORE execution; no internal retry loop,
        // fallback, fresh relative deadline, changed point or budget reset.
        // Diagnostic clocks are both reserved BEFORE the real wait. A refused
        // reservation never enters the syscall or performs an uncharged read.
        #[cfg(target_os = "macos")]
        {
            charge(Charge::InstantClockRead)?;
            charge(Charge::InstantClockRead)?;
        }
        // Last guarded reservation is directly before the witness and syscall,
        // after planning and diagnostic reservations. Caller charges its clock.
        charge(match kind {
            WaitKind::Coarse => Charge::AbsoluteCoarseWait,
            WaitKind::Fine => Charge::AbsoluteFineWait,
        })?;
        #[cfg(target_os = "macos")]
        let entered = {
            let entered = Instant::now();
            self.last_observation = Some(WaitObservation {
                point,
                wake,
                entered,
                returned: None,
                #[cfg(test)]
                status: None,
                coarse: kind == WaitKind::Coarse,
                #[cfg(test)]
                backend: "darwin_kevent64_critical_absolute",
            });
            entered
        };
        use std::os::fd::AsRawFd;
        // Plain data output; ident/filter/flags are checked before accepting it.
        let mut event: libc::kevent64_s = unsafe { std::mem::zeroed() };
        // SAFETY: fresh owned queue, one initialized input/output and valid timeout.
        // A single absolute one-shot timer, no callbacks or unrelated thread changes.
        let status = unsafe {
            libc::kevent64(
                self.timer_queue.as_raw_fd(),
                &request,
                1,
                &mut event,
                1,
                0,
                &timeout,
            )
        };
        // Preserve native errno before any diagnostic clock/other library call.
        let native_error = (status < 0).then(|| io::Error::last_os_error().kind());
        #[cfg(target_os = "macos")]
        {
            let returned = Instant::now(); // Already reserved above.
            self.last_observation = Some(WaitObservation {
                point,
                wake,
                entered,
                returned: Some(returned),
                #[cfg(test)]
                status: Some(status),
                coarse: kind == WaitKind::Coarse,
                #[cfg(test)]
                backend: "darwin_kevent64_critical_absolute",
            });
        }
        validate_critical_timer_result(status, native_error, &request, &event)?;
        // Zero is a bounded watchdog return, never proof of point admission.
        Ok(Outcome::AbsoluteWaitReturned)
    }
}

// NOTE_MACHTIME binds both units and epoch to the same conservative Mach
// mapping. NOTE_CRITICAL and explicit zero leeway request minimal coalescing;
// they do not guarantee scheduling. The watchdog is capped by the old request.
#[cfg(target_os = "macos")]
fn critical_timer_request(
    raw: u64,
    duration: Duration,
) -> io::Result<(libc::kevent64_s, libc::timespec)> {
    if raw == 0 || raw > i64::MAX as u64 || duration.is_zero() || duration > COARSE_CAP {
        return Err(phase(
            io::ErrorKind::InvalidData,
            "darwin_critical_timer_request",
        ));
    }
    Ok((
        libc::kevent64_s {
            ident: 1,
            filter: libc::EVFILT_TIMER,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_CRITICAL
                | libc::NOTE_LEEWAY
                | libc::NOTE_MACHTIME
                | libc::NOTE_ABSOLUTE,
            data: raw as i64,
            udata: raw,
            ext: [0, 0],
        },
        libc::timespec {
            tv_sec: 0,
            tv_nsec: duration.as_nanos() as libc::c_long,
        },
    ))
}

#[cfg(target_os = "macos")]
fn validate_critical_timer_result(
    status: i32,
    native_error: Option<io::ErrorKind>,
    request: &libc::kevent64_s,
    event: &libc::kevent64_s,
) -> io::Result<()> {
    if status < 0 {
        return Err(phase(
            native_error.unwrap_or(io::ErrorKind::Other),
            "darwin_critical_timer_wait",
        ));
    }
    if status == 0 {
        return Ok(()); // No event: original caller clock still decides admission.
    }
    if status != 1 {
        return Err(phase(
            io::ErrorKind::InvalidData,
            "darwin_critical_timer_count",
        ));
    }
    if event.flags & libc::EV_ERROR != 0 {
        return Err(phase(
            io::ErrorKind::Other,
            "darwin_critical_timer_registration",
        ));
    }
    if event.ident != request.ident
        || event.filter != libc::EVFILT_TIMER
        || event.udata != request.udata
        || event.data <= 0
    {
        return Err(phase(
            io::ErrorKind::InvalidData,
            "darwin_critical_timer_event",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    #[test]
    fn critical_timer_result_refuses_stale_wrong_and_error_events() {
        let (request, _) = critical_timer_request(12345, FINE_CAP).unwrap();
        let valid = || libc::kevent64_s {
            ident: 1,
            filter: libc::EVFILT_TIMER,
            flags: 0,
            fflags: 0,
            data: 1,
            udata: 12345,
            ext: [0, 0],
        };
        assert!(validate_critical_timer_result(1, None, &request, &valid()).is_ok());
        assert!(validate_critical_timer_result(0, None, &request, &valid()).is_ok());
        assert!(validate_critical_timer_result(2, None, &request, &valid()).is_err());
        assert_eq!(
            validate_critical_timer_result(
                -1,
                Some(io::ErrorKind::Interrupted),
                &request,
                &valid()
            )
            .unwrap_err()
            .kind(),
            io::ErrorKind::Interrupted
        );
        for kind in 0..5 {
            let mut bad = valid();
            match kind {
                0 => bad.ident = 2,
                1 => bad.filter = libc::EVFILT_READ,
                2 => bad.udata = 12344,
                3 => bad.data = 0,
                _ => bad.flags = libc::EV_ERROR,
            }
            assert!(validate_critical_timer_result(1, None, &request, &bad).is_err());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn critical_timer_final_guard_refusal_precedes_actual_wait_and_witness() {
        let mut waiter = DarwinAbsoluteWait::new(|_| Ok(())).unwrap();
        let point = Instant::now() + Duration::from_millis(5);
        let mut attempts = 0;
        let result = waiter.wait_bounded(point, |kind| {
            if matches!(kind, Charge::AbsoluteCoarseWait | Charge::AbsoluteFineWait) {
                attempts += 1;
                return Err(phase(io::ErrorKind::TimedOut, "test_original_cutoff"));
            }
            Ok(())
        });
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!(attempts, 1);
        assert!(waiter.last_observation.is_none());
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn critical_timer_actual_native_call_retains_original_point_and_backend() {
        let mut waiter = DarwinAbsoluteWait::new(|_| Ok(())).unwrap();
        let point = Instant::now() + Duration::from_millis(5);
        let outcome = waiter.wait_bounded(point, |_| Ok(())).unwrap();
        assert_eq!(outcome, Outcome::AbsoluteWaitReturned);
        let observed = waiter.last_observation.expect("actual owned kernel call");
        assert_eq!(observed.point, point);
        assert_eq!(observed.backend, "darwin_kevent64_critical_absolute");
        assert!(matches!(observed.status, Some(0 | 1)));
        assert!(observed.returned.is_some());
        // This proves syscall/witness execution, not a scheduler latency bound.
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn critical_timer_contract_uses_original_mach_epoch_and_zero_leeway() {
        for duration in [FINE_CAP, COARSE_CAP] {
            let (event, timeout) = critical_timer_request(1234567, duration).unwrap();
            assert_eq!(event.data, 1234567);
            assert_eq!(event.udata, 1234567);
            assert_eq!(event.filter, libc::EVFILT_TIMER);
            assert_eq!(
                event.fflags,
                libc::NOTE_MACHTIME | libc::NOTE_ABSOLUTE | libc::NOTE_CRITICAL | libc::NOTE_LEEWAY
            );
            assert_eq!(
                event.flags,
                libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT
            );
            assert_eq!(event.ext, [0, 0]);
            assert_eq!(timeout.tv_sec, 0);
            assert_eq!(timeout.tv_nsec as u128, duration.as_nanos());
        }
        for raw in [0, i64::MAX as u64 + 1, u64::MAX] {
            assert!(critical_timer_request(raw, FINE_CAP).is_err());
        }
        for duration in [Duration::ZERO, COARSE_CAP + Duration::from_nanos(1)] {
            assert!(critical_timer_request(123, duration).is_err());
        }
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn critical_timer_create_refusal_precedes_any_owned_descriptor() {
        let mut creations = 0;
        let result = DarwinAbsoluteWait::new(|kind| {
            if kind == Charge::TimerCreate {
                creations += 1;
                return Err(phase(
                    io::ErrorKind::PermissionDenied,
                    "test_creation_refusal",
                ));
            }
            Ok(())
        });
        assert!(matches!(result, Err(e) if e.kind() == io::ErrorKind::PermissionDenied));
        assert_eq!(creations, 1);
    }
    #[cfg(target_os = "macos")]
    #[test]
    fn critical_timer_owned_descriptor_closes_on_drop() {
        use std::os::fd::AsRawFd;
        let waiter = DarwinAbsoluteWait::new(|_| Ok(())).unwrap();
        let fd = waiter.timer_queue.as_raw_fd();
        assert!(unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0);
        drop(waiter);
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_GETFD) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }

    #[test]
    fn native_wait_errors_preserve_typed_protocol_phase() {
        for (kind, label) in [
            (io::ErrorKind::TimedOut, "windows_timer_original_cutoff"),
            (io::ErrorKind::Other, "windows_highres_timer_wait"),
            (
                io::ErrorKind::Interrupted,
                "darwin_absolute_wait_interrupted",
            ),
        ] {
            let error = phase(kind, label);
            assert_eq!(error.kind(), kind);
            let typed = error
                .get_ref()
                .and_then(|value| value.downcast_ref::<super::super::Phase>());
            assert_eq!(typed.map(|value| value.0), Some(label));
        }
        let external = io::Error::new(io::ErrorKind::TimedOut, "external socket timeout");
        assert!(external
            .get_ref()
            .and_then(|value| value.downcast_ref::<super::super::Phase>())
            .is_none());
    }
    #[test]
    fn nonunit_timebase_maps_early_by_checked_floor() {
        assert_eq!(map_early(100, 125, 125, 3).unwrap(), 102);
        assert_eq!(map_early(100, 126, 125, 3).unwrap(), 102);
        assert_eq!(map_early(100, 0, 125, 3).unwrap(), 100);
    }
    #[test]
    fn invalid_timebase_and_all_overflows_refuse() {
        assert!(map_early(1, 1, 0, 1).is_err());
        assert!(map_early(1, 1, 1, 0).is_err());
        assert!(map_early(1, u128::MAX, 1, 2).is_err());
        assert!(map_early(1, u128::from(u64::MAX) + 2, 1, 1).is_err());
        assert!(map_early(u64::MAX, 2, 1, 1).is_err());
    }
    #[test]
    fn expired_point_does_not_get_fresh_wait_or_allowance() {
        let n = Instant::now();
        assert_eq!(plan(n, n).unwrap(), Err(Outcome::PointReached));
        assert_eq!(
            plan(n + Duration::from_millis(11), n).unwrap(),
            Err(Outcome::PointReached)
        );
    }
    #[test]
    fn fine_window_caps_requests_and_keeps_original_active_tail() {
        let n = Instant::now();
        assert_eq!(
            plan(n, n + Duration::from_micros(20)).unwrap(),
            Err(Outcome::ActiveTail)
        );
        assert_eq!(
            plan(n, n + Duration::from_millis(3)).unwrap(),
            Err(Outcome::OutsideFineWindow)
        );
        assert_eq!(
            plan(n, n + Duration::from_micros(30)).unwrap(),
            Ok(n + Duration::from_micros(10))
        );
        assert_eq!(
            plan(n, n + Duration::from_millis(2)).unwrap(),
            Ok(n + FINE_CAP)
        );
    }
    #[test]
    fn later_observation_never_moves_original_point_or_tail() {
        let n = Instant::now();
        let point = n + Duration::from_micros(100);
        let first = plan(n, point).unwrap().unwrap();
        let last = plan(n + Duration::from_micros(70), point).unwrap().unwrap();
        assert_eq!(first, n + FINE_CAP);
        assert_eq!(last, point - ACTIVE_TAIL);
        assert_eq!(
            plan(n + Duration::from_micros(90), point).unwrap(),
            Err(Outcome::ActiveTail)
        );
        // Same desired absolute wake always maps identically; retry observation
        // cannot shift the origin or accumulate relative-sleep drift.
        let unchanged_origin_offset = last.duration_since(n).as_nanos();
        assert_eq!(
            map_early(100, unchanged_origin_offset, 125, 3).unwrap(),
            2019
        );
    }
    #[test]
    fn bounded_coarse_preserves_one_ms_cap_and_original_two_ms_guard() {
        let n = Instant::now();
        assert_eq!(
            plan_bounded(n, n + Duration::from_millis(3)).unwrap(),
            Ok((n + COARSE_CAP, WaitKind::Coarse))
        );
        assert_eq!(
            plan_bounded(n, n + Duration::from_micros(2100)).unwrap(),
            Ok((n + Duration::from_micros(100), WaitKind::Coarse))
        );
        assert_eq!(
            plan_bounded(n, n + Duration::from_millis(2)).unwrap(),
            Ok((n + FINE_CAP, WaitKind::Fine))
        );
    }
    #[test]
    fn coarse_to_fine_transition_uses_unchanged_original_point() {
        let n = Instant::now();
        let point = n + Duration::from_millis(3);
        let coarse = plan_bounded(n, point).unwrap().unwrap();
        let fine = plan_bounded(n + Duration::from_millis(1), point)
            .unwrap()
            .unwrap();
        assert_eq!(coarse, (n + COARSE_CAP, WaitKind::Coarse));
        assert_eq!(fine, (n + Duration::from_micros(1050), WaitKind::Fine));
        assert_eq!(
            plan_bounded(n + Duration::from_micros(2980), point).unwrap(),
            Err(Outcome::ActiveTail)
        );
        assert_eq!(
            plan_bounded(point + Duration::from_millis(11), point).unwrap(),
            Err(Outcome::PointReached)
        );
    }
    #[test]
    fn late_coarse_observation_has_no_restarted_relative_window() {
        let n = Instant::now();
        let point = n + Duration::from_millis(3);
        // A genuinely late return cannot be reinterpreted as a new3ms interval.
        assert_eq!(
            plan_bounded(n + Duration::from_millis(4), point).unwrap(),
            Err(Outcome::PointReached)
        );
        assert_eq!(map_early(100, 1_000_000, 125, 3).unwrap(), 24099);
    }
}

// Windows refinement: request expiration from the same absolute Rust point.
// Waitable timers use relative100ns due time, NOT UTC absolute time; original
// Instant cutoff is still checked before/after every bounded syscall sequence.
#[cfg(any(windows, test))]
fn windows_relative_due(delay_ns: u128) -> io::Result<Option<i64>> {
    let units = delay_ns / 100; // floor: never add rounding to requested sleep
    if units == 0 {
        return Ok(None);
    }
    let units = i64::try_from(units)
        .map_err(|_| phase(io::ErrorKind::InvalidInput, "windows_timer_due_overflow"))?;
    Ok(Some(-units))
}
#[cfg(any(windows, test))]
fn windows_timeout_ms(remaining_ns: u128) -> io::Result<u32> {
    if remaining_ns == 0 {
        return Err(phase(
            io::ErrorKind::TimedOut,
            "windows_timer_original_cutoff",
        ));
    }
    let ms = remaining_ns
        .checked_add(999_999)
        .ok_or_else(|| phase(io::ErrorKind::InvalidInput, "windows_timer_wait_overflow"))?
        / 1_000_000;
    let ms = u32::try_from(ms)
        .map_err(|_| phase(io::ErrorKind::InvalidInput, "windows_timer_wait_overflow"))?;
    // INFINITE is never an admitted custody boundary. Ceil is API granularity,
    // not accepted lateness: the actual Instant is rechecked after the call.
    if ms == u32::MAX {
        return Err(phase(
            io::ErrorKind::InvalidInput,
            "windows_timer_wait_overflow",
        ));
    }
    Ok(ms)
}
#[cfg(any(windows, test))]
fn windows_cutoff(
    point: Instant,
    original_end: Instant,
    allowance: Duration,
    latest_return: Option<Instant>,
) -> io::Result<Instant> {
    // Keep both original limits, then apply the separate already-admitted
    // service boundary. It is not a new point, session end, or extra allowance.
    let original_limit = point
        .checked_add(allowance)
        .map(|limit| limit.min(original_end))
        .ok_or_else(|| phase(io::ErrorKind::InvalidInput, "windows_timer_clock_overflow"))?;
    Ok(latest_return.map_or(original_limit, |latest| original_limit.min(latest)))
}
// WAIT_OBJECT_0 reports a signalled timer, not delivery admission. Keep the
// original session end exclusive and the original delivery cutoff inclusive.
#[cfg(any(windows, test))]
fn windows_wait_return_exceeds_cutoff(
    returned: Instant,
    original_end: Instant,
    cutoff: Instant,
) -> bool {
    returned >= original_end || returned > cutoff
}
#[cfg(windows)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum WindowsCharge {
    ClockRead,
    TimerCreate,
    TimerArm,
    TimerWait,
}
// Test-only per-owned wait metadata. Opaque Instants are retained internally
// for identity checks; this type deliberately has no Debug/Serialize impl.
#[cfg(all(test, windows))]
#[derive(Clone, Copy)]
pub(super) struct WindowsWaitObservation {
    pub(super) point: Instant,
    pub(super) original_end: Instant,
    pub(super) cutoff: Option<Instant>,
    pub(super) wake: Option<Instant>,
    pub(super) coarse: Option<bool>,
    pub(super) due_100ns: Option<i64>,
    pub(super) watchdog_ms: Option<u32>,
    pub(super) stage: &'static str,
    pub(super) entered: Option<Instant>,
    pub(super) returned: Option<Instant>,
    pub(super) guard_observed: Option<Instant>,
    pub(super) status: Option<u32>,
    pub(super) native_error_kind: Option<io::ErrorKind>,
    pub(super) refusal_kind: Option<io::ErrorKind>,
}
#[cfg(all(test, windows))]
impl WindowsWaitObservation {
    pub(super) fn new(point: Instant, original_end: Instant) -> Self {
        Self {
            point,
            original_end,
            cutoff: None,
            wake: None,
            coarse: None,
            due_100ns: None,
            watchdog_ms: None,
            stage: "cutoff_derivation",
            entered: None,
            returned: None,
            guard_observed: None,
            status: None,
            native_error_kind: None,
            refusal_kind: None,
        }
    }
    // All emitted fields are selected numerical/static metadata. Never emit
    // raw Instants, native error text/code, addresses, handles or payload.
    pub(super) fn metadata(self) -> serde_json::Value {
        let ns = |later: Instant, earlier: Instant| -> u64 {
            later
                .saturating_duration_since(earlier)
                .as_nanos()
                .try_into()
                .unwrap_or(u64::MAX)
        };
        let safe_kind = |kind: io::ErrorKind| match kind {
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::Interrupted => "interrupted",
            io::ErrorKind::InvalidData => "invalid_data",
            io::ErrorKind::InvalidInput => "invalid_input",
            io::ErrorKind::PermissionDenied => "permission_denied",
            _ => "other",
        };
        serde_json::json!({
            "backend": "owned_windows_high_resolution_waitable_timer",
            "stage": self.stage,
            "coarse": self.coarse,
            "due_100ns": self.due_100ns,
            "watchdog_ms": self.watchdog_ms,
            "entered": self.entered.is_some(),
            "returned": self.returned.is_some(),
            "status_semantics": "WaitForSingleObject_return_code",
            "status": self.status,
            "native_error_kind": self.native_error_kind.map(safe_kind),
            "refusal_kind": self.refusal_kind.map(safe_kind),
            "requested_interval_ns": self.wake.zip(self.entered).map(|(w,e)| ns(w,e)),
            "request_expired_before_entry": self.wake.zip(self.entered).map(|(w,e)| e >= w),
            "call_interval_ns": self.returned.zip(self.entered).map(|(r,e)| ns(r,e)),
            "wake_overshoot_ns": self.returned.zip(self.wake).map(|(r,w)| ns(r,w)),
            "point_lateness_at_return_ns": self.returned.map(|r| ns(r,self.point)),
            "cutoff_exceeded_at_return": self.returned.zip(self.cutoff).map(|(r,c)| r > c),
            "original_end_reached_at_return": self.returned.map(|r| r >= self.original_end),
            "guard_original_end_reached": self.guard_observed.map(|n| n >= self.original_end),
            "guard_cutoff_reached": self.guard_observed.zip(self.cutoff).map(|(n,c)| n >= c),
            "guard_cutoff_exceeded": self.guard_observed.zip(self.cutoff).map(|(n,c)| n > c),
            "guard_point_lateness_ns": self.guard_observed.map(|n| ns(n,self.point)),
        })
    }
}
#[cfg(all(test, windows))]
fn reserve_windows_observer_clocks(
    charge: &mut impl FnMut(WindowsCharge) -> io::Result<()>,
) -> io::Result<()> {
    // Both reservations precede ALL observation reads and the native wait.
    charge(WindowsCharge::ClockRead)?;
    charge(WindowsCharge::ClockRead)
}
#[cfg(windows)]
pub(super) struct WindowsHighResolutionWait {
    // OwnedHandle is Send; no Copy/raw-handle duplication or unsafe impl Send.
    timer: std::os::windows::io::OwnedHandle,
    #[cfg(test)]
    pub(super) last_observation: Option<WindowsWaitObservation>,
}
#[cfg(windows)]
impl WindowsHighResolutionWait {
    pub(super) fn new(mut charge: impl FnMut(WindowsCharge) -> io::Result<()>) -> io::Result<Self> {
        use std::os::windows::io::FromRawHandle;
        use windows_sys::Win32::System::Threading::{
            CreateWaitableTimerExW, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
            SYNCHRONIZATION_SYNCHRONIZE, TIMER_MODIFY_STATE,
        };
        charge(WindowsCharge::TimerCreate)?;
        // SAFETY: NULL attributes/name creates an unnamed non-inheritable,
        // synchronization timer. No public namespace/global timer settings.
        let raw = unsafe {
            CreateWaitableTimerExW(
                std::ptr::null(),
                std::ptr::null(),
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                SYNCHRONIZATION_SYNCHRONIZE | TIMER_MODIFY_STATE,
            )
        };
        if raw.is_null() {
            return Err(phase(io::ErrorKind::Other, "windows_highres_timer_create"));
        }
        // SAFETY: successful new unnamed handle belongs exclusively to this
        // object. OwnedHandle closes it on every error/drop and is never cloned.
        let timer = unsafe { std::os::windows::io::OwnedHandle::from_raw_handle(raw) };
        Ok(Self {
            timer,
            #[cfg(test)]
            last_observation: None,
        })
    }
    pub(super) fn wait_bounded(
        &mut self,
        point: Instant,
        original_end: Instant,
        allowance: Duration,
        latest_return: Option<Instant>,
        mut charge: impl FnMut(WindowsCharge) -> io::Result<()>,
    ) -> io::Result<Outcome> {
        #[cfg(test)]
        {
            self.last_observation = Some(WindowsWaitObservation::new(point, original_end));
        }
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT},
            System::Threading::{SetWaitableTimerEx, WaitForSingleObject},
        };
        let cutoff = windows_cutoff(point, original_end, allowance, latest_return)?;
        #[cfg(test)]
        if let Some(w) = &mut self.last_observation {
            w.cutoff = Some(cutoff);
        }
        #[cfg(test)]
        self.diagnostic_stage("initial_clock");
        charge(WindowsCharge::ClockRead)?;
        let now = Instant::now();
        if now >= original_end || now > cutoff {
            #[cfg(test)]
            self.diagnostic_stage("initial_cutoff");
            #[cfg(test)]
            if let Some(w) = &mut self.last_observation {
                w.guard_observed = Some(now);
            }
            return Err(phase(
                io::ErrorKind::TimedOut,
                "windows_timer_initial_cutoff",
            ));
        }
        let (wake, kind) = match plan_bounded(now, point)? {
            Ok(plan) => plan,
            Err(outcome) => return Ok(outcome),
        };
        #[cfg(test)]
        if let Some(w) = &mut self.last_observation {
            w.wake = Some(wake);
            w.coarse = Some(kind == WaitKind::Coarse);
        }
        #[cfg(not(test))]
        let _ = kind;
        #[cfg(test)]
        self.diagnostic_stage("arm_work_reservation");
        charge(WindowsCharge::TimerArm)?;
        #[cfg(test)]
        self.diagnostic_stage("before_arm_clock");
        charge(WindowsCharge::ClockRead)?;
        let arm_now = Instant::now();
        if arm_now >= original_end || arm_now > cutoff {
            #[cfg(test)]
            self.diagnostic_stage("before_arm_cutoff");
            #[cfg(test)]
            if let Some(w) = &mut self.last_observation {
                w.guard_observed = Some(arm_now);
            }
            return Err(phase(
                io::ErrorKind::TimedOut,
                "windows_timer_before_arm_cutoff",
            ));
        }
        // Syscall setup may consume this bounded wake; don't reset its origin.
        let remaining = match wake.checked_duration_since(arm_now) {
            Some(remaining) => remaining,
            None => return Ok(Outcome::WindowsWaitReturned),
        };
        let due = match windows_relative_due(remaining.as_nanos())? {
            Some(due) => due,
            None => return Ok(Outcome::ActiveTail),
        };
        #[cfg(test)]
        if let Some(w) = &mut self.last_observation {
            w.due_100ns = Some(due);
        }
        // SAFETY: exclusively owned live HANDLE; stack i64 due pointer remains
        // valid for this synchronous call; no period/APC/wakeup/coalescing delay.
        #[cfg(test)]
        self.diagnostic_stage("native_arm");
        let armed = unsafe {
            SetWaitableTimerEx(
                self.timer.as_raw_handle(),
                &due,
                0,
                None,
                std::ptr::null(),
                std::ptr::null(),
                0,
            )
        };
        if armed == 0 {
            #[cfg(test)]
            {
                let kind = io::Error::last_os_error().kind();
                if let Some(w) = &mut self.last_observation {
                    w.native_error_kind = Some(kind);
                }
            }
            return Err(phase(io::ErrorKind::Other, "windows_highres_timer_arm"));
        }
        #[cfg(test)]
        self.diagnostic_stage("after_arm_clock");
        charge(WindowsCharge::ClockRead)?;
        let after_arm = Instant::now();
        if after_arm >= original_end || after_arm > cutoff {
            #[cfg(test)]
            self.diagnostic_stage("after_arm_cutoff");
            #[cfg(test)]
            if let Some(w) = &mut self.last_observation {
                w.guard_observed = Some(after_arm);
            }
            return Err(phase(
                io::ErrorKind::TimedOut,
                "windows_timer_after_arm_cutoff",
            ));
        }
        #[cfg(test)]
        self.diagnostic_stage("wait_work_reservation");
        charge(WindowsCharge::TimerWait)?;
        #[cfg(test)]
        self.diagnostic_stage("before_wait_clock");
        charge(WindowsCharge::ClockRead)?;
        let wait_now = Instant::now();
        if wait_now >= original_end || wait_now >= cutoff {
            #[cfg(test)]
            self.diagnostic_stage("before_wait_cutoff");
            #[cfg(test)]
            if let Some(w) = &mut self.last_observation {
                w.guard_observed = Some(wait_now);
            }
            return Err(phase(
                io::ErrorKind::TimedOut,
                "windows_timer_before_wait_cutoff",
            ));
        }
        let timeout = windows_timeout_ms(cutoff.duration_since(wait_now).as_nanos())?;
        #[cfg(test)]
        {
            self.diagnostic_stage("diagnostic_wait_clock_reservation");
            if let Some(w) = &mut self.last_observation {
                w.watchdog_ms = Some(timeout);
            }
            // Reserve BOTH bracket clocks before entering the actual call.
            // A refusal here does not manufacture an entered/returned witness.
            reserve_windows_observer_clocks(&mut charge)?;
            let entered = Instant::now();
            // Extra diagnostics never permit an entered call after the same
            // original custody limit. This clock was reserved above.
            if entered >= original_end || entered >= cutoff {
                self.diagnostic_stage("diagnostic_entry_cutoff");
                #[cfg(test)]
                if let Some(w) = &mut self.last_observation {
                    w.guard_observed = Some(entered);
                }
                return Err(phase(
                    io::ErrorKind::TimedOut,
                    "windows_timer_diagnostic_entry_cutoff",
                ));
            }
            self.diagnostic_stage("native_wait");
            if let Some(w) = &mut self.last_observation {
                w.entered = Some(entered);
            }
        }
        // SAFETY: no concurrent close/borrow; finite timeout never INFINITE.
        // Cancellation is observed by the owned loop on return, not fabricated.
        let status = unsafe { WaitForSingleObject(self.timer.as_raw_handle(), timeout) };
        #[cfg(test)]
        {
            // GetLastError must be captured before Instant::now or any observer.
            let kind = (status == windows_sys::Win32::Foundation::WAIT_FAILED)
                .then(|| io::Error::last_os_error().kind());
            let returned = Instant::now();
            if let Some(w) = &mut self.last_observation {
                w.status = Some(status);
                w.native_error_kind = kind;
                w.returned = Some(returned);
            }
        }
        #[cfg(test)]
        self.diagnostic_stage("after_wait_clock");
        charge(WindowsCharge::ClockRead)?;
        let after_wait = Instant::now();
        if windows_wait_return_exceeds_cutoff(after_wait, original_end, cutoff) {
            #[cfg(test)]
            self.diagnostic_stage("after_wait_cutoff");
            #[cfg(test)]
            if let Some(w) = &mut self.last_observation {
                w.guard_observed = Some(after_wait);
            }
            return Err(phase(
                io::ErrorKind::TimedOut,
                "windows_timer_after_wait_cutoff",
            ));
        }
        #[cfg(test)]
        self.diagnostic_stage("native_wait_result");
        match status {
            WAIT_OBJECT_0 => Ok(Outcome::WindowsWaitReturned),
            WAIT_TIMEOUT => Err(phase(
                io::ErrorKind::TimedOut,
                "windows_highres_timer_timeout",
            )),
            _ => Err(phase(io::ErrorKind::Other, "windows_highres_timer_wait")),
        }
    }
    #[cfg(test)]
    fn diagnostic_stage(&mut self, stage: &'static str) {
        if let Some(w) = &mut self.last_observation {
            w.stage = stage;
        }
    }
}
#[cfg(test)]
mod windows_plan_tests {
    use super::*;
    #[test]
    fn negative_due_is_checked_floor_without_extra_quantum() {
        assert_eq!(windows_relative_due(0).unwrap(), None);
        assert_eq!(windows_relative_due(99).unwrap(), None);
        assert_eq!(windows_relative_due(100).unwrap(), Some(-1));
        assert_eq!(windows_relative_due(50_099).unwrap(), Some(-500));
        assert_eq!(windows_relative_due(1_000_000).unwrap(), Some(-10_000));
        assert!(windows_relative_due(u128::MAX).is_err());
    }
    #[test]
    fn native_wait_ceiling_has_no_infinite_zero_or_overflow_boundary() {
        assert_eq!(windows_timeout_ms(1).unwrap(), 1);
        assert_eq!(windows_timeout_ms(1_000_000).unwrap(), 1);
        assert_eq!(windows_timeout_ms(10_000_000).unwrap(), 10);
        assert!(windows_timeout_ms(0).is_err());
        assert!(windows_timeout_ms(u128::MAX).is_err());
        assert!(windows_timeout_ms(u128::from(u32::MAX) * 1_000_000).is_err());
    }
    #[test]
    fn custody_limit_is_existing_point_allowance_or_earlier_original_end() {
        let n = Instant::now();
        let point = n + Duration::from_millis(3);
        let allowance = Duration::from_millis(10);
        assert_eq!(
            windows_cutoff(point, n + Duration::from_secs(1), allowance, None).unwrap(),
            n + Duration::from_millis(13)
        );
        assert_eq!(
            windows_cutoff(point, n + Duration::from_millis(4), allowance, None).unwrap(),
            n + Duration::from_millis(4)
        );
        assert_eq!(
            plan_bounded(n + Duration::from_millis(14), point).unwrap(),
            Err(Outcome::PointReached)
        );
    }
    #[test]
    fn recorded_signalled_timer_returns_refuse_without_expiring_session_budget() {
        let origin = Instant::now();
        let point = origin + Duration::from_millis(3);
        let original_end = origin + Duration::from_secs(40);
        let cutoff = windows_cutoff(point, original_end, Duration::from_millis(10), None).unwrap();
        // Exact point lateness from CI38166840585 / Windows job114551051522.
        // Each underlying wait returned WAIT_OBJECT_0. These synthetic clock
        // offsets replay the production admission guard, not the Windows API
        // or a claim about which component caused the observed latency.
        for point_lateness_ns in [59_194_400, 42_961_900, 39_580_132] {
            let returned = point + Duration::from_nanos(point_lateness_ns);
            assert!(returned < original_end);
            assert!(windows_wait_return_exceeds_cutoff(
                returned,
                original_end,
                cutoff
            ));
        }
    }

    #[test]
    fn timer_return_cutoff_equality_does_not_extend_original_session_end() {
        let origin = Instant::now();
        let point = origin + Duration::from_millis(3);
        let allowance = Duration::from_millis(10);
        let original_end = origin + Duration::from_secs(1);
        let cutoff = windows_cutoff(point, original_end, allowance, None).unwrap();
        assert!(!windows_wait_return_exceeds_cutoff(
            cutoff,
            original_end,
            cutoff
        ));
        assert!(windows_wait_return_exceeds_cutoff(
            cutoff + Duration::from_nanos(1),
            original_end,
            cutoff
        ));
        // Session expiry is independently exclusive even when it supplies
        // the tighter effective cutoff; delivery equality cannot reopen it.
        let earlier_end = point + Duration::from_millis(5);
        let tighter = windows_cutoff(point, earlier_end, allowance, None).unwrap();
        assert_eq!(tighter, earlier_end);
        assert!(!windows_wait_return_exceeds_cutoff(
            earlier_end - Duration::from_nanos(1),
            earlier_end,
            tighter
        ));
        assert!(windows_wait_return_exceeds_cutoff(
            earlier_end,
            earlier_end,
            tighter
        ));
        assert!(windows_wait_return_exceeds_cutoff(
            original_end,
            original_end,
            cutoff
        ));
    }

    #[test]
    fn pending_service_latest_return_never_receives_second_allowance() {
        let origin = Instant::now();
        let original_end = origin + Duration::from_secs(1);
        let nominal = origin + Duration::from_millis(5);
        let allowance = Duration::from_millis(10);
        let delivery_end = nominal + allowance;
        // Waiting for service retry at its final deadline must not append a
        // second release allowance to that already bounded service deadline.
        assert_eq!(
            windows_cutoff(delivery_end, original_end, allowance, Some(delivery_end)).unwrap(),
            delivery_end
        );
    }

    #[test]
    fn latest_return_none_keeps_original_limit_and_earlier_end() {
        let origin = Instant::now();
        let point = origin + Duration::from_millis(3);
        let allowance = Duration::from_millis(10);
        let long_end = origin + Duration::from_secs(1);
        assert_eq!(
            windows_cutoff(point, long_end, allowance, None).unwrap(),
            point + allowance
        );
        let earlier_end = origin + Duration::from_millis(4);
        assert_eq!(
            windows_cutoff(point, earlier_end, allowance, Some(long_end)).unwrap(),
            earlier_end
        );
        let looser_pending = point + Duration::from_millis(20);
        assert_eq!(
            windows_cutoff(point, long_end, allowance, Some(looser_pending)).unwrap(),
            point + allowance
        );
        assert!(
            windows_cutoff(origin, long_end, Duration::MAX, Some(origin)).is_err(),
            "a tighter pending boundary must not hide original point arithmetic overflow"
        );
    }

    #[cfg(windows)]
    #[test]
    fn expired_pending_boundary_refuses_before_actual_rearm_and_keeps_original_end() {
        let mut timer = WindowsHighResolutionWait::new(|_| Ok(())).unwrap();
        let now = Instant::now();
        let point = now + Duration::from_millis(100);
        let original_end = now + Duration::from_secs(1);
        let pending_end = now - Duration::from_nanos(1);
        let mut arms = 0;
        let mut waits = 0;
        let result = timer.wait_bounded(
            point,
            original_end,
            Duration::from_millis(10),
            Some(pending_end),
            |kind| {
                match kind {
                    WindowsCharge::TimerArm => arms += 1,
                    WindowsCharge::TimerWait => waits += 1,
                    _ => {}
                }
                Ok(())
            },
        );
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert_eq!((arms, waits), (0, 0));
        let observed = timer.last_observation.unwrap();
        assert_eq!(observed.point, point);
        assert_eq!(observed.original_end, original_end);
        assert_eq!(observed.cutoff, Some(pending_end));
        assert_eq!(observed.stage, "initial_cutoff");
        assert!(observed.entered.is_none() && observed.returned.is_none());
    }

    #[cfg(windows)]
    #[test]
    fn diagnostic_bracket_budget_refusal_never_enters_measured_operation() {
        for available in [0, 1] {
            let mut remaining = available;
            let mut attempted = 0;
            let mut operation_entered = false;
            let result = (|| -> io::Result<()> {
                reserve_windows_observer_clocks(&mut |kind| {
                    assert_eq!(kind, WindowsCharge::ClockRead);
                    attempted += 1;
                    if remaining == 0 {
                        return Err(phase(io::ErrorKind::InvalidData, "fixture_work_budget"));
                    }
                    remaining -= 1;
                    Ok(())
                })?;
                operation_entered = true;
                Ok(())
            })();
            assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
            assert!(!operation_entered);
            assert_eq!(attempted, available + 1);
            assert_eq!(remaining, 0);
        }
    }
    #[cfg(windows)]
    #[test]
    fn diagnostic_metadata_has_closed_safe_keys_and_no_opaque_clocks() {
        let n = Instant::now();
        let mut w =
            WindowsWaitObservation::new(n + Duration::from_millis(3), n + Duration::from_secs(1));
        w.cutoff = Some(n + Duration::from_millis(13));
        w.wake = Some(n + Duration::from_millis(1));
        w.entered = Some(n);
        w.returned = Some(n + Duration::from_millis(2));
        w.due_100ns = Some(-10_000);
        w.watchdog_ms = Some(13);
        w.status = Some(windows_sys::Win32::Foundation::WAIT_OBJECT_0);
        let m = w.metadata();
        let allowed = [
            "backend",
            "stage",
            "coarse",
            "due_100ns",
            "watchdog_ms",
            "entered",
            "returned",
            "status_semantics",
            "status",
            "native_error_kind",
            "refusal_kind",
            "requested_interval_ns",
            "request_expired_before_entry",
            "call_interval_ns",
            "wake_overshoot_ns",
            "point_lateness_at_return_ns",
            "cutoff_exceeded_at_return",
            "original_end_reached_at_return",
            "guard_original_end_reached",
            "guard_cutoff_reached",
            "guard_cutoff_exceeded",
            "guard_point_lateness_ns",
        ];
        assert_eq!(m.as_object().unwrap().len(), allowed.len());
        assert!(m
            .as_object()
            .unwrap()
            .keys()
            .all(|k| allowed.contains(&k.as_str())));
        assert_eq!(m["call_interval_ns"], 2_000_000);
        assert_eq!(m["wake_overshoot_ns"], 1_000_000);
        assert_eq!(m["watchdog_ms"], 13);
        assert!(!m.to_string().contains("Instant"));
    }
    #[cfg(windows)]
    #[test]
    fn refused_creation_budget_executes_no_timer_creation() {
        let mut charged = 0;
        let result = WindowsHighResolutionWait::new(|_| {
            charged += 1;
            Err(phase(io::ErrorKind::Other, "fixture_work_budget"))
        });
        assert!(result.is_err());
        assert_eq!(charged, 1);
    }
    #[cfg(windows)]
    #[test]
    fn refused_arm_budget_does_not_enter_native_wait() {
        let mut timer = WindowsHighResolutionWait::new(|_| Ok(())).unwrap();
        let n = Instant::now();
        let mut clocks = 0;
        let mut arms = 0;
        let mut waits = 0;
        let result = timer.wait_bounded(
            n + Duration::from_millis(100),
            n + Duration::from_secs(1),
            Duration::from_millis(10),
            None,
            |kind| {
                match kind {
                    WindowsCharge::ClockRead => clocks += 1,
                    WindowsCharge::TimerArm => {
                        arms += 1;
                        return Err(phase(io::ErrorKind::Other, "fixture_work_budget"));
                    }
                    WindowsCharge::TimerWait => waits += 1,
                    WindowsCharge::TimerCreate => panic!("unexpected duplicate timer creation"),
                }
                Ok(())
            },
        );
        assert!(result.is_err());
        assert_eq!((clocks, arms, waits), (1, 1, 0));
    }
    #[cfg(windows)]
    #[test]
    fn owned_timer_is_send_and_original_cutoff_prevents_rearm() {
        let timer = WindowsHighResolutionWait::new(|_| Ok(())).unwrap();
        std::thread::spawn(move || {
            let mut timer = timer;
            let point = Instant::now();
            let mut calls = 0;
            let result = timer.wait_bounded(point, point, Duration::from_millis(10), None, |_| {
                calls += 1;
                Ok(())
            });
            let error = result.unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::TimedOut);
            assert_eq!(
                error
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<super::super::Phase>()
                    .unwrap()
                    .0,
                "windows_timer_initial_cutoff"
            );
            assert_eq!(calls, 1);
            let observation = timer.last_observation.unwrap();
            assert_eq!(observation.stage, "initial_cutoff");
            assert_eq!(observation.point, point);
            assert!(observation.entered.is_none());
            assert!(observation.returned.is_none());
            assert!(observation.status.is_none());
        })
        .join()
        .unwrap();
    }
}
