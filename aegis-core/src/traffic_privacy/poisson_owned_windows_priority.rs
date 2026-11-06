//! Ordinary requested CPU priority for ONE dedicated owned Windows thread.
//! No process mutation, realtime class, effective-priority or latency guarantee.
use super::{io, Phase};

#[cfg(not(test))]
pub(super) struct Observation;
#[cfg(test)]
#[derive(Clone, Copy, serde::Serialize)]
pub(super) struct Observation {
    pub(super) process_class: u32,
    pub(super) prior_relative: i32,
    pub(super) requested_relative: i32,
    pub(super) requested_base: i32,
    pub(super) changed: bool,
}
#[derive(Clone, Copy)]
pub(super) enum Boundary {
    BeforeNative,
    AfterNative,
}
trait Backend {
    type Thread: Copy;
    type Process: Copy;
    fn current_thread(&mut self) -> io::Result<Self::Thread>;
    fn current_process(&mut self) -> io::Result<Self::Process>;
    fn class(&mut self, process: Self::Process) -> io::Result<u32>;
    fn priority(&mut self, thread: Self::Thread) -> io::Result<i32>;
    fn set(&mut self, thread: Self::Thread, relative: i32) -> io::Result<()>;
}
fn failure(kind: io::ErrorKind, phase: &'static str) -> io::Error {
    io::Error::new(kind, Phase(phase))
}
fn request(class: u32, prior: i32) -> io::Result<(i32, i32)> {
    // The time-critical relative value maps to base15 in every admitted
    // non-realtime process class. +2 in BELOW_NORMAL only reached base8 and
    // repeatedly resumed after the original10ms cutoff on hosted Windows.
    // This dedicated nonblocking worker keeps finite work/clock budgets and
    // bounded native waits. No process class, foreign or pool thread is changed.
    if !matches!(class, 0x40 | 0x4000 | 0x20 | 0x8000) {
        return Err(failure(
            io::ErrorKind::PermissionDenied,
            "owned_windows_priority_class",
        ));
    }
    if !matches!(prior, -15 | -2..=2 | 15) {
        return Err(failure(
            io::ErrorKind::InvalidData,
            "owned_windows_priority_relative",
        ));
    }
    Ok((15, 15))
}
fn observed<T>(
    checkpoint: &mut impl FnMut(Boundary) -> io::Result<()>,
    operation: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    checkpoint(Boundary::BeforeNative)?;
    // Native backend captures GetLastError before the clock/checkpoint below.
    let result = operation();
    checkpoint(Boundary::AfterNative)?;
    result
}
fn configure<B: Backend>(
    backend: &mut B,
    checkpoint: &mut impl FnMut(Boundary) -> io::Result<()>,
) -> io::Result<Observation> {
    let thread = observed(checkpoint, || backend.current_thread())?;
    let process = observed(checkpoint, || backend.current_process())?;
    let process_class = observed(checkpoint, || backend.class(process))?;
    request(process_class, 0)?;
    let prior_relative = observed(checkpoint, || backend.priority(thread))?;
    let (requested_relative, requested_base) = request(process_class, prior_relative)?;
    let changed = requested_relative != prior_relative;
    if changed {
        observed(checkpoint, || backend.set(thread, requested_relative))?;
    }
    let actual = observed(checkpoint, || backend.priority(thread))?;
    if actual != requested_relative {
        return Err(failure(
            io::ErrorKind::PermissionDenied,
            "owned_windows_priority_readback",
        ));
    }
    if observed(checkpoint, || backend.class(process))? != process_class {
        return Err(failure(
            io::ErrorKind::PermissionDenied,
            "owned_windows_priority_class_changed",
        ));
    }
    // Concurrent external class changes are not atomic with this readback.
    #[cfg(test)]
    let observation = Observation {
        process_class,
        prior_relative,
        requested_relative,
        requested_base,
        changed,
    };
    #[cfg(not(test))]
    let observation = {
        let _ = requested_base;
        Observation
    };
    Ok(observation)
}

#[cfg(windows)]
struct Native;
#[cfg(windows)]
fn last_error(phase: &'static str) -> io::Error {
    let kind = io::Error::last_os_error().kind();
    failure(kind, phase)
}
#[cfg(windows)]
impl Backend for Native {
    type Thread = windows_sys::Win32::Foundation::HANDLE;
    type Process = windows_sys::Win32::Foundation::HANDLE;
    fn current_thread(&mut self) -> io::Result<Self::Thread> {
        // SAFETY: current owned thread pseudo-handle; never closed or escaped.
        Ok(unsafe { windows_sys::Win32::System::Threading::GetCurrentThread() })
    }
    fn current_process(&mut self) -> io::Result<Self::Process> {
        // SAFETY: read-only current process pseudo-handle; never closed/escaped.
        Ok(unsafe { windows_sys::Win32::System::Threading::GetCurrentProcess() })
    }
    fn class(&mut self, process: Self::Process) -> io::Result<u32> {
        // SAFETY: live current-process pseudo-handle obtained in this thread.
        let value = unsafe { windows_sys::Win32::System::Threading::GetPriorityClass(process) };
        if value == 0 {
            Err(last_error("owned_windows_priority_query_class"))
        } else {
            Ok(value)
        }
    }
    fn priority(&mut self, thread: Self::Thread) -> io::Result<i32> {
        // SAFETY: live current-thread pseudo-handle; no foreign thread access.
        let value = unsafe { windows_sys::Win32::System::Threading::GetThreadPriority(thread) };
        // THREAD_PRIORITY_ERROR_RETURN is MAXLONG (documented Win32 sentinel).
        if value == i32::MAX {
            Err(last_error("owned_windows_priority_query_relative"))
        } else {
            Ok(value)
        }
    }
    fn set(&mut self, thread: Self::Thread, relative: i32) -> io::Result<()> {
        // SAFETY: validated non-realtime process class and base15 on this dedicated current thread;
        // no process, background-mode, boost, realtime or pool mutation.
        let value =
            unsafe { windows_sys::Win32::System::Threading::SetThreadPriority(thread, relative) };
        if value == 0 {
            Err(last_error("owned_windows_priority_set"))
        } else {
            Ok(())
        }
    }
}
#[cfg(windows)]
pub(super) fn initialize(
    checkpoint: &mut impl FnMut(Boundary) -> io::Result<()>,
) -> io::Result<Observation> {
    configure(&mut Native, checkpoint)
}
#[cfg(test)]
#[path = "poisson_owned_windows_priority_tests.rs"]
mod tests;
