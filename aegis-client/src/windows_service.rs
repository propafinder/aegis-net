use crate::{run_client, Args};
use anyhow::Context;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Mutex, OnceLock};
use tokio::sync::watch;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_INTERROGATE,
    SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

static SERVICE_ARGS: OnceLock<Mutex<Option<Args>>> = OnceLock::new();
static SERVICE_STOP_TX: OnceLock<Mutex<Option<watch::Sender<bool>>>> = OnceLock::new();
static SERVICE_STATUS_HANDLE_CELL: OnceLock<Mutex<usize>> = OnceLock::new();
static LIFECYCLE: Mutex<ServiceLifecycle> = Mutex::new(ServiceLifecycle::new());
static FAILURE_STAGE: AtomicU32 = AtomicU32::new(1);

/// Stable, non-sensitive SCM diagnostics: 10=config, 20=ingress selection,
/// 30=listener/runtime initialization, 50=running.
pub(crate) fn stage(code: u32) {
    FAILURE_STAGE.store(code, Ordering::Relaxed);
}

#[derive(Clone, Copy)]
struct ServiceLifecycle {
    state: u32,
    checkpoint: u32,
    exit_code: u32,
}

impl ServiceLifecycle {
    const fn new() -> Self {
        Self {
            state: SERVICE_START_PENDING,
            checkpoint: 1,
            exit_code: 0,
        }
    }

    fn transition(&mut self, state: u32, exit_code: u32) {
        // Readiness racing a stop callback must never resurrect a service.
        if state == SERVICE_RUNNING && self.state != SERVICE_START_PENDING {
            return;
        }
        self.state = state;
        self.exit_code = exit_code;
        self.checkpoint = if matches!(state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
            self.checkpoint.saturating_add(1)
        } else {
            0
        };
    }

    fn status(self) -> SERVICE_STATUS {
        let pending = matches!(self.state, SERVICE_START_PENDING | SERVICE_STOP_PENDING);
        SERVICE_STATUS {
            dwServiceType: SERVICE_WIN32_OWN_PROCESS,
            dwCurrentState: self.state,
            dwControlsAccepted: if self.state == SERVICE_RUNNING {
                SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
            } else {
                0
            },
            dwWin32ExitCode: if self.exit_code == 0 { 0 } else { 1066 },
            dwServiceSpecificExitCode: self.exit_code,
            dwCheckPoint: self.checkpoint,
            dwWaitHint: if pending { 30_000 } else { 0 },
        }
    }
}

/// Called only after configuration, state and ingress initialization succeed.
pub(crate) fn ready() {
    stage(50);
    report_status(SERVICE_RUNNING, 0);
}

pub fn run(args: Args) -> anyhow::Result<()> {
    SERVICE_ARGS
        .set(Mutex::new(Some(args)))
        .map_err(|_| anyhow::anyhow!("windows service args already initialized"))?;
    SERVICE_STOP_TX
        .set(Mutex::new(None))
        .map_err(|_| anyhow::anyhow!("windows service stop channel already initialized"))?;
    SERVICE_STATUS_HANDLE_CELL
        .set(Mutex::new(0))
        .map_err(|_| anyhow::anyhow!("windows service status handle already initialized"))?;

    let mut service_name = wide_null("AegisClient");
    let mut service_table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];

    let ok = unsafe { StartServiceCtrlDispatcherW(service_table.as_mut_ptr()) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error()).context("start service control dispatcher");
    }
    Ok(())
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide_null("AegisClient");
    let handle =
        RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(service_control_handler), ptr::null());
    if handle.is_null() {
        return;
    }
    set_status_handle(handle);
    report_status(SERVICE_START_PENDING, 0);

    let args = match SERVICE_ARGS
        .get()
        .and_then(|cell| cell.lock().ok())
        .and_then(|mut guard| guard.take())
    {
        Some(args) => args,
        None => {
            report_status(SERVICE_STOPPED, 1);
            return;
        }
    };

    let (stop_tx, stop_rx) = watch::channel(false);
    if let Some(cell) = SERVICE_STOP_TX.get() {
        if let Ok(mut guard) = cell.lock() {
            *guard = Some(stop_tx);
        }
    }

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")
        .and_then(|runtime| {
            runtime.block_on(async {
            let client = run_client(args, Some(stop_rx));
            tokio::pin!(client);
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                tokio::select! {
                    result = &mut client => break result,
                    _ = interval.tick() => {
                        if let Ok(mut state) = LIFECYCLE.lock() {
                            if matches!(state.state, SERVICE_START_PENDING | SERVICE_STOP_PENDING) {
                                state.checkpoint = state.checkpoint.saturating_add(1);
                                publish_status(state.status());
                            }
                        }
                    }
                }
            }
        })
        });

    // Errors can contain config, destinations and credentials. SCM receives a
    // stable failure code; do not bypass the client's private-log policy with
    // an unprotected ProgramData file.
    let exit_code = if result.is_ok() {
        0
    } else {
        FAILURE_STAGE.load(Ordering::Relaxed)
    };
    report_status(SERVICE_STOPPED, exit_code);
}

unsafe extern "system" fn service_control_handler(
    control: u32,
    _event_type: u32,
    _event_data: *mut c_void,
    _context: *mut c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            report_status(SERVICE_STOP_PENDING, 0);
            if let Some(cell) = SERVICE_STOP_TX.get() {
                if let Ok(guard) = cell.lock() {
                    if let Some(tx) = guard.as_ref() {
                        let _ = tx.send(true);
                    }
                }
            }
            0
        }
        SERVICE_CONTROL_INTERROGATE => {
            if let Ok(state) = LIFECYCLE.lock() {
                publish_status(state.status());
            }
            0
        }
        _ => 0,
    }
}

fn report_status(current_state: u32, win32_exit_code: u32) {
    if let Ok(mut state) = LIFECYCLE.lock() {
        state.transition(current_state, win32_exit_code);
        publish_status(state.status());
    }
}

fn publish_status(status: SERVICE_STATUS) {
    let handle = status_handle();
    if handle.is_null() {
        return;
    }
    unsafe {
        SetServiceStatus(handle, &status);
    }
}

fn set_status_handle(handle: SERVICE_STATUS_HANDLE) {
    if let Some(cell) = SERVICE_STATUS_HANDLE_CELL.get() {
        if let Ok(mut guard) = cell.lock() {
            *guard = handle as usize;
        }
    }
}

fn status_handle() -> SERVICE_STATUS_HANDLE {
    SERVICE_STATUS_HANDLE_CELL
        .get()
        .and_then(|cell| {
            cell.lock()
                .ok()
                .map(|guard| *guard as SERVICE_STATUS_HANDLE)
        })
        .unwrap_or(ptr::null_mut())
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialization_failure_never_claims_running() {
        let mut state = ServiceLifecycle::new();
        assert_eq!(state.status().dwControlsAccepted, 0);
        state.transition(SERVICE_STOPPED, 1);
        let status = state.status();
        assert_eq!(status.dwCurrentState, SERVICE_STOPPED);
        assert_eq!(status.dwWin32ExitCode, 1066);
        assert_eq!(status.dwServiceSpecificExitCode, 1);
        assert_eq!(status.dwWaitHint, 0);
    }

    #[test]
    fn interrogate_and_late_readiness_preserve_stop_pending() {
        let mut state = ServiceLifecycle::new();
        state.transition(SERVICE_RUNNING, 0);
        assert_eq!(
            state.status().dwControlsAccepted,
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        );
        state.transition(SERVICE_STOP_PENDING, 0);
        let checkpoint = state.status().dwCheckPoint;
        state.transition(SERVICE_RUNNING, 0);
        assert_eq!(state.status().dwCurrentState, SERVICE_STOP_PENDING);
        assert_eq!(state.status().dwCheckPoint, checkpoint);
    }
}
