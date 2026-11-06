//! Ordinary requested QoS for ONE dedicated owned Darwin thread.
//! No realtime/effective-class guarantee, borrowed thread, pool or override.
use super::{io, Phase};

const USER_INTERACTIVE: u32 = 0x21;
const USER_INITIATED: u32 = 0x19;
#[cfg(not(any(test, target_os = "macos")))]
pub(super) struct Observation;
#[cfg(any(test, target_os = "macos"))]
#[derive(Clone, Copy, serde::Serialize)]
pub(super) struct Observation {
    pub(super) prior_class: u32,
    pub(super) prior_relative: i32,
    pub(super) requested_class: u32,
    pub(super) requested_relative: i32,
    pub(super) changed: bool,
}
#[derive(Clone, Copy)]
pub(super) enum Boundary {
    BeforeNative,
    AfterNative,
}
trait Backend {
    type Thread: Copy;
    fn current(&mut self) -> io::Result<Self::Thread>;
    fn read(&mut self, thread: Self::Thread) -> io::Result<(u32, i32)>;
    fn set_self(&mut self, class: u32, relative: i32) -> io::Result<()>;
}
fn failure(kind: io::ErrorKind, phase: &'static str) -> io::Error {
    io::Error::new(kind, Phase(phase))
}
fn valid_requested(class: u32, relative: i32) -> bool {
    matches!(
        class,
        0 | 0x09 | 0x11 | 0x15 | USER_INITIATED | USER_INTERACTIVE
    ) && (-15..=0).contains(&relative)
}
fn configure<B: Backend>(
    backend: &mut B,
    checkpoint: &mut impl FnMut(Boundary) -> io::Result<()>,
) -> io::Result<Observation> {
    checkpoint(Boundary::BeforeNative)?;
    let current = backend.current();
    checkpoint(Boundary::AfterNative)?;
    let thread = current?;
    checkpoint(Boundary::BeforeNative)?;
    let read = backend.read(thread);
    checkpoint(Boundary::AfterNative)?;
    let (prior_class, prior_relative) = read?;
    if !valid_requested(prior_class, prior_relative) {
        return Err(failure(
            io::ErrorKind::InvalidData,
            "owned_qos_prior_invalid",
        ));
    }
    // Preserve an already higher class and its relative setting.
    let (requested_class, requested_relative) = if prior_class == USER_INTERACTIVE {
        (prior_class, prior_relative)
    } else {
        (USER_INITIATED, 0)
    };
    let changed = (prior_class, prior_relative) != (requested_class, requested_relative);
    if changed {
        checkpoint(Boundary::BeforeNative)?;
        let set = backend.set_self(requested_class, requested_relative);
        checkpoint(Boundary::AfterNative)?;
        set?;
    }
    checkpoint(Boundary::BeforeNative)?;
    let read = backend.read(thread);
    checkpoint(Boundary::AfterNative)?;
    let observed = read?;
    if observed != (requested_class, requested_relative) {
        return Err(failure(
            io::ErrorKind::PermissionDenied,
            "owned_qos_readback_mismatch",
        ));
    }
    #[cfg(any(test, target_os = "macos"))]
    let observation = Observation {
        prior_class,
        prior_relative,
        requested_class,
        requested_relative,
        changed,
    };
    #[cfg(not(any(test, target_os = "macos")))]
    let observation = Observation;
    Ok(observation)
}

#[cfg(target_os = "macos")]
struct Native;
#[cfg(target_os = "macos")]
fn returned(code: libc::c_int, phase: &'static str) -> io::Result<()> {
    if code == 0 {
        return Ok(());
    }
    let kind = match code {
        libc::EPERM => io::ErrorKind::PermissionDenied,
        libc::EINVAL => io::ErrorKind::InvalidInput,
        _ => io::ErrorKind::Other,
    };
    Err(failure(kind, phase))
}
#[cfg(target_os = "macos")]
impl Backend for Native {
    type Thread = libc::pthread_t;
    fn current(&mut self) -> io::Result<Self::Thread> {
        // SAFETY: call on the dedicated current thread; token never escapes.
        Ok(unsafe { libc::pthread_self() })
    }
    fn read(&mut self, thread: Self::Thread) -> io::Result<(u32, i32)> {
        let mut class = libc::qos_class_t::QOS_CLASS_UNSPECIFIED;
        let mut relative = 0;
        // SAFETY: live local thread token; valid aligned initialized outputs.
        // Apple documents the enum values the getter may write.
        let result = unsafe { libc::pthread_get_qos_class_np(thread, &mut class, &mut relative) };
        returned(result, "owned_qos_query")?;
        Ok((class as u32, relative))
    }
    fn set_self(&mut self, class: u32, relative: i32) -> io::Result<()> {
        // No transmute of untrusted u32; caller only selects initiated here.
        let class = match class {
            USER_INITIATED => libc::qos_class_t::QOS_CLASS_USER_INITIATED,
            _ => return Err(failure(io::ErrorKind::InvalidInput, "owned_qos_class")),
        };
        // SAFETY: changes ONLY this dedicated current thread's ordinary QoS.
        returned(
            unsafe { libc::pthread_set_qos_class_self_np(class, relative) },
            "owned_qos_set",
        )
    }
}
#[cfg(target_os = "macos")]
pub(super) fn initialize(
    checkpoint: &mut impl FnMut(Boundary) -> io::Result<()>,
) -> io::Result<Observation> {
    configure(&mut Native, checkpoint)
}

// A bounded Mach soft-realtime request on the dedicated owned release thread.
// The kernel may still schedule late; the original 10 ms refusal remains.
#[cfg(target_os = "macos")]
#[repr(C)]
struct DiagnosticMachTimebase {
    numer: u32,
    denom: u32,
}
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_timebase_info(info: *mut DiagnosticMachTimebase) -> libc::c_int;
}
#[cfg(target_os = "macos")]
pub(super) fn initialize_time_constraint(
    checkpoint: &mut impl FnMut(Boundary) -> io::Result<()>,
) -> io::Result<()> {
    let mut tb = DiagnosticMachTimebase { numer: 0, denom: 0 };
    checkpoint(Boundary::BeforeNative)?;
    let timebase = unsafe { mach_timebase_info(&mut tb) };
    checkpoint(Boundary::AfterNative)?;
    if timebase != 0 || tb.numer == 0 || tb.denom == 0 {
        return Err(failure(io::ErrorKind::InvalidData, "diag_mach_timebase"));
    }
    let ticks = |ns: u64| -> io::Result<u32> {
        let value = u128::from(ns)
            .checked_mul(u128::from(tb.denom))
            .ok_or_else(|| failure(io::ErrorKind::InvalidData, "diag_mach_ticks"))?
            / u128::from(tb.numer);
        u32::try_from(value)
            .ok()
            .filter(|&value| value > 0)
            .ok_or_else(|| failure(io::ErrorKind::InvalidData, "diag_mach_ticks"))
    };
    let mut requested = libc::thread_time_constraint_policy_data_t {
        period: ticks(10_000_000)?,
        computation: ticks(1_000_000)?,
        constraint: ticks(2_000_000)?,
        preemptible: 1,
    };
    checkpoint(Boundary::BeforeNative)?;
    let thread = unsafe { libc::pthread_mach_thread_np(libc::pthread_self()) };
    checkpoint(Boundary::AfterNative)?;
    if thread == 0 {
        return Err(failure(io::ErrorKind::InvalidData, "diag_mach_thread"));
    }
    checkpoint(Boundary::BeforeNative)?;
    let set = unsafe {
        libc::thread_policy_set(
            thread,
            libc::THREAD_TIME_CONSTRAINT_POLICY as libc::thread_policy_flavor_t,
            (&mut requested as *mut libc::thread_time_constraint_policy_data_t).cast(),
            libc::THREAD_TIME_CONSTRAINT_POLICY_COUNT,
        )
    };
    checkpoint(Boundary::AfterNative)?;
    if set != 0 {
        return Err(failure(io::ErrorKind::PermissionDenied, "diag_mach_set"));
    }
    let mut observed = libc::thread_time_constraint_policy_data_t {
        period: 0,
        computation: 0,
        constraint: 0,
        preemptible: 0,
    };
    let mut count = libc::THREAD_TIME_CONSTRAINT_POLICY_COUNT;
    let mut default = 0;
    checkpoint(Boundary::BeforeNative)?;
    let get = unsafe {
        libc::thread_policy_get(
            thread,
            libc::THREAD_TIME_CONSTRAINT_POLICY as libc::thread_policy_flavor_t,
            (&mut observed as *mut libc::thread_time_constraint_policy_data_t).cast(),
            &mut count,
            &mut default,
        )
    };
    checkpoint(Boundary::AfterNative)?;
    #[cfg(any(
        test,
        all(feature = "diagnostic-mach-time-constraint", debug_assertions)
    ))]
    if let Some(path) = std::env::var_os("AEGIS_DIAG_MACH_POLICY_LOG") {
        use std::io::Write;
        let diagnostic = format!("diag_mach_policy=set:{set} get:{get} count:{count} default:{default} requested:{},{},{},{} observed:{},{},{},{}\n",
            requested.period, requested.computation, requested.constraint, requested.preemptible,
            observed.period, observed.computation, observed.constraint, observed.preemptible);
        let mut log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        log.write_all(diagnostic.as_bytes())?;
    }
    if get != 0
        || default != 0
        || count != libc::THREAD_TIME_CONSTRAINT_POLICY_COUNT
        || observed.period != requested.period
        || observed.computation != requested.computation
        || observed.constraint != requested.constraint
        || observed.preemptible != requested.preemptible
    {
        return Err(failure(
            io::ErrorKind::PermissionDenied,
            "diag_mach_readback",
        ));
    }
    Ok(())
}
#[cfg(test)]
#[path = "poisson_owned_qos_tests.rs"]
mod tests;
