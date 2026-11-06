//! Native SCM operations: numeric status, bounded waits, least-privilege service.
use super::{ServiceCommand, ServiceNameArg, WinctlError};
use serde_json::{json, Value};
use std::{
    io, mem,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr, thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::System::Threading::{
    OpenProcess, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};
use windows_sys::Win32::{Foundation::*, System::Services::*};

struct Handle(SC_HANDLE);
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}
impl Handle {
    fn new(handle: SC_HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}

fn wide(value: &str) -> io::Result<Vec<u16>> {
    if value.contains('\0') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "NUL in service argument",
        ));
    }
    Ok(value.encode_utf16().chain(Some(0)).collect())
}
fn manager(access: u32) -> io::Result<Handle> {
    Handle::new(unsafe { OpenSCManagerW(ptr::null(), ptr::null(), access) })
}
fn open(name: &str, access: u32) -> io::Result<Handle> {
    let manager = manager(SC_MANAGER_CONNECT)?;
    let name = wide(name)?;
    Handle::new(unsafe { OpenServiceW(manager.0, name.as_ptr(), access) })
}
fn status(service: &Handle) -> io::Result<SERVICE_STATUS_PROCESS> {
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut size = 0;
    let ok = unsafe {
        QueryServiceStatusEx(
            service.0,
            SC_STATUS_PROCESS_INFO,
            (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
            mem::size_of_val(&status) as u32,
            &mut size,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(status)
    }
}
fn state_name(state: u32) -> &'static str {
    match state {
        SERVICE_STOPPED => "STOPPED",
        SERVICE_START_PENDING => "START_PENDING",
        SERVICE_STOP_PENDING => "STOP_PENDING",
        SERVICE_RUNNING => "RUNNING",
        SERVICE_PAUSED => "PAUSED",
        SERVICE_PAUSE_PENDING => "PAUSE_PENDING",
        SERVICE_CONTINUE_PENDING => "CONTINUE_PENDING",
        _ => "UNKNOWN",
    }
}
pub(super) fn query(name: &str) -> Result<Value, WinctlError> {
    let handle = match open(name, SERVICE_QUERY_STATUS) {
        Ok(handle) => handle,
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            return Ok(json!({"name":name,"exists":false}));
        }
        Err(error) => return Err(error.into()),
    };
    let s = status(&handle)?;
    Ok(
        json!({"name":name,"exists":true,"state":state_name(s.dwCurrentState),
        "state_code":s.dwCurrentState,"process_id":s.dwProcessId,
        "win32_exit_code":s.dwWin32ExitCode,"service_exit_code":s.dwServiceSpecificExitCode}),
    )
}

fn set_start_type(name: &str, start_type: u32) -> Result<(), WinctlError> {
    let handle = open(name, SERVICE_CHANGE_CONFIG)?;
    if unsafe {
        ChangeServiceConfigW(
            handle.0,
            SERVICE_NO_CHANGE,
            start_type,
            SERVICE_NO_CHANGE,
            ptr::null(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

/// A queued SCM failure restart is not cancelable; disabling the service
/// before StopService prevents it from re-arming after an explicit disconnect.
pub(super) fn disable_then_stop(name: &str) -> Result<Value, WinctlError> {
    set_start_type(name, SERVICE_DISABLED)?;
    run(ServiceCommand::Stop(ServiceNameArg {
        service_name: name.to_owned(),
    }))
}

pub(super) fn auto_start_then_start(name: &str) -> Result<Value, WinctlError> {
    set_start_type(name, SERVICE_AUTO_START)?;
    run(ServiceCommand::Start(ServiceNameArg {
        service_name: name.to_owned(),
    }))
}

fn wait(service: &Handle, expected: u32) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let current = status(service)?;
        if current.dwCurrentState == expected {
            return Ok(());
        }
        if expected == SERVICE_RUNNING && current.dwCurrentState == SERVICE_STOPPED {
            return Err(io::Error::other(format!(
                "service stopped during initialization: win32={} service={}",
                current.dwWin32ExitCode, current.dwServiceSpecificExitCode
            )));
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service transition timed out",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}
fn stop(handle: &Handle) -> io::Result<()> {
    let snapshot = status(handle)?;
    let current = snapshot.dwCurrentState;
    if current == SERVICE_STOPPED {
        return Ok(());
    }
    // SERVICE_STOPPED acknowledges the control request before ServiceMain and
    // the process necessarily return. Keep a handle to this process before
    // stopping it; otherwise uninstall can race its still-mapped executable.
    // Shared-process services must not wait for unrelated services to exit.
    let process =
        if snapshot.dwServiceType & SERVICE_WIN32_OWN_PROCESS != 0 && snapshot.dwProcessId != 0 {
            let raw = unsafe { OpenProcess(PROCESS_SYNCHRONIZE, 0, snapshot.dwProcessId) };
            if raw.is_null() {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32)
                    && status(handle)?.dwCurrentState == SERVICE_STOPPED
                {
                    return Ok(());
                }
                return Err(error);
            }
            Some(unsafe { OwnedHandle::from_raw_handle(raw) })
        } else {
            None
        };
    if current != SERVICE_STOP_PENDING {
        let mut s = SERVICE_STATUS::default();
        if unsafe { ControlService(handle.0, SERVICE_CONTROL_STOP, &mut s) } == 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
                return Err(error);
            }
        }
    }
    wait(handle, SERVICE_STOPPED)?;
    if let Some(process) = process {
        match unsafe { WaitForSingleObject(process.as_raw_handle(), 45_000) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "service reported stopped but its process has not exited",
                ));
            }
            _ => return Err(io::Error::last_os_error()),
        }
    }
    Ok(())
}

fn wait_removed(name: &str) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        match open(name, SERVICE_QUERY_STATUS) {
            Ok(handle) => drop(handle),
            Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
                return Ok(())
            }
            Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_MARKED_FOR_DELETE as i32) => {}
            Err(error) => return Err(error),
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "service deletion pending; close external SCM handles and retry",
            ));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

pub(super) fn require_binary_in(name: &str, expected: &std::path::Path) -> Result<(), WinctlError> {
    let handle = match open(name, SERVICE_QUERY_CONFIG) {
        Ok(handle) => handle,
        Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
            return Ok(())
        }
        Err(error) => return Err(error.into()),
    };
    let mut size = 0;
    unsafe {
        QueryServiceConfigW(handle.0, ptr::null_mut(), 0, &mut size);
    }
    if size == 0 || size > 65536 {
        return Err(io::Error::other("service configuration size rejected").into());
    }
    let mut storage = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
    let config = storage.as_mut_ptr().cast::<QUERY_SERVICE_CONFIGW>();
    if unsafe { QueryServiceConfigW(handle.0, config, size, &mut size) } == 0 {
        return Err(io::Error::last_os_error().into());
    }
    let binary = unsafe { (*config).lpBinaryPathName };
    if binary.is_null() || (binary as usize) < storage.as_ptr() as usize {
        return Err(io::Error::other("service binary path missing").into());
    }
    let mut length = 0;
    let end = storage.as_ptr() as usize + storage.len() * mem::size_of::<usize>();
    while (binary as usize).saturating_add((length + 1) * 2) <= end {
        if unsafe { *binary.add(length) } == 0 {
            break;
        }
        length += 1;
    }
    let command = String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(binary, length) });
    if !command_owns_binary(&command, expected)? {
        return Err(WinctlError::ArtifactValidation(
            "service belongs to another installation; refusing to stop it".into(),
        ));
    }
    Ok(())
}

fn command_owns_binary(command: &str, expected: &std::path::Path) -> io::Result<bool> {
    let Some((binary, arguments)) = command
        .strip_prefix('"')
        .and_then(|value| value.split_once('"'))
    else {
        return Ok(false);
    };
    if !arguments.starts_with(" --config ") {
        return Ok(false);
    }
    let binary = std::path::Path::new(binary);
    if !binary.is_absolute() || !expected.is_absolute() {
        return Ok(false);
    }
    // Accept canonical/extended-length spellings of the same owned file, but
    // never follow a mutable junction/symlink in an SCM executable path.
    aegis_core::windows_file::reject_reparse_ancestry(binary)?;
    aegis_core::windows_file::reject_reparse_ancestry(expected)?;
    Ok(binary
        .canonicalize()?
        .to_string_lossy()
        .eq_ignore_ascii_case(&expected.canonicalize()?.to_string_lossy()))
}

pub(super) fn run(command: ServiceCommand) -> Result<Value, WinctlError> {
    let (name, action) = match command {
        ServiceCommand::Status(arg) => {
            return Ok(json!({"ok":true,"service":query(&arg.service_name)?}))
        }
        ServiceCommand::Install(arg) => {
            // A command line with an unquoted executable is ambiguous to SCM.
            if !arg.bin_path.starts_with('"')
                || !arg.bin_path.contains("\" --config ")
                || !arg.bin_path.ends_with(" --windows-service")
            {
                return Err(WinctlError::ArtifactValidation(
                    "service requires a quoted client path, --config and final --windows-service"
                        .into(),
                ));
            }
            let start = match arg.start.as_str() {
                "demand" => SERVICE_DEMAND_START,
                "auto" => SERVICE_AUTO_START,
                "disabled" => SERVICE_DISABLED,
                _ => {
                    return Err(WinctlError::ArtifactValidation(
                        "invalid service startup type".into(),
                    ))
                }
            };
            let manager = manager(SC_MANAGER_CREATE_SERVICE)?;
            let name = wide(&arg.service_name)?;
            let display = wide(&arg.display_name)?;
            let bin = wide(&arg.bin_path)?;
            let account = wide("NT AUTHORITY\\LocalService")?;
            let _service = Handle::new(unsafe {
                CreateServiceW(
                    manager.0,
                    name.as_ptr(),
                    display.as_ptr(),
                    SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_START | DELETE,
                    SERVICE_WIN32_OWN_PROCESS,
                    start,
                    SERVICE_ERROR_NORMAL,
                    bin.as_ptr(),
                    ptr::null(),
                    ptr::null_mut(),
                    ptr::null(),
                    if arg.system_tunnel {
                        ptr::null()
                    } else {
                        account.as_ptr()
                    },
                    ptr::null(),
                )
            })?;
            if arg.system_tunnel {
                let mut actions = [
                    SC_ACTION {
                        Type: SC_ACTION_RESTART,
                        Delay: 1000,
                    },
                    SC_ACTION {
                        Type: SC_ACTION_RESTART,
                        Delay: 5000,
                    },
                    SC_ACTION {
                        Type: SC_ACTION_RESTART,
                        Delay: 15000,
                    },
                ];
                let failure = SERVICE_FAILURE_ACTIONSW {
                    dwResetPeriod: 3600,
                    lpRebootMsg: ptr::null_mut(),
                    lpCommand: ptr::null_mut(),
                    cActions: actions.len() as u32,
                    lpsaActions: actions.as_mut_ptr(),
                };
                let flag = SERVICE_FAILURE_ACTIONS_FLAG {
                    fFailureActionsOnNonCrashFailures: 1,
                };
                if unsafe {
                    ChangeServiceConfig2W(
                        _service.0,
                        SERVICE_CONFIG_FAILURE_ACTIONS,
                        (&failure as *const SERVICE_FAILURE_ACTIONSW).cast(),
                    )
                } == 0
                    || unsafe {
                        ChangeServiceConfig2W(
                            _service.0,
                            SERVICE_CONFIG_FAILURE_ACTIONS_FLAG,
                            (&flag as *const SERVICE_FAILURE_ACTIONS_FLAG).cast(),
                        )
                    } == 0
                {
                    let error = io::Error::last_os_error();
                    unsafe {
                        DeleteService(_service.0);
                    }
                    return Err(error.into());
                }
            }
            (arg.service_name, "install")
        }
        ServiceCommand::Start(arg) => {
            let handle = open(&arg.service_name, SERVICE_START | SERVICE_QUERY_STATUS)?;
            if status(&handle)?.dwCurrentState != SERVICE_RUNNING {
                if unsafe { StartServiceW(handle.0, 0, ptr::null()) } == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
                        return Err(error.into());
                    }
                }
                wait(&handle, SERVICE_RUNNING)?;
            }
            (arg.service_name, "start")
        }
        ServiceCommand::Stop(arg) => {
            let handle = open(&arg.service_name, SERVICE_STOP | SERVICE_QUERY_STATUS)?;
            stop(&handle)?;
            (arg.service_name, "stop")
        }
        ServiceCommand::Uninstall(arg) => {
            match open(
                &arg.service_name,
                SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE,
            ) {
                Ok(handle) => {
                    stop(&handle)?;
                    if unsafe { DeleteService(handle.0) } == 0 {
                        return Err(io::Error::last_os_error().into());
                    }
                }
                Err(error) if error.raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST as i32) => {
                }
                Err(error) => return Err(error.into()),
            }
            // DeleteService marks the entry; the process and all SCM handles
            // must actually close before reporting a completed uninstall.
            wait_removed(&arg.service_name)?;
            (arg.service_name, "uninstall")
        }
    };
    Ok(json!({"ok":true,"service_name":name,"action":action,"service":query(&name)?}))
}
pub(super) fn command_line(
    client: &std::path::Path,
    config: &std::path::Path,
    online_bundle: Option<&std::path::Path>,
) -> Result<String, WinctlError> {
    if [Some(client), Some(config), online_bundle]
        .into_iter()
        .flatten()
        .any(|p| !p.is_absolute() || p.to_string_lossy().contains(['"', '\0']))
    {
        return Err(WinctlError::ArtifactValidation(
            "ambiguous service path".into(),
        ));
    }
    let online = online_bundle
        .map(|p| format!(" --device-online-bundle \"{}\"", p.display()))
        .unwrap_or_default();
    Ok(format!(
        "\"{}\" --config \"{}\"{online} --windows-service",
        client.display(),
        config.display()
    ))
}
pub(super) fn replace_binary(
    name: &str,
    client: &std::path::Path,
    config: &std::path::Path,
    online_bundle: Option<&std::path::Path>,
) -> Result<(), WinctlError> {
    let command = command_line(client, config, online_bundle)?;
    let value = wide(&command)?;
    let handle = open(name, SERVICE_CHANGE_CONFIG | SERVICE_QUERY_STATUS)?;
    if status(&handle)?.dwCurrentState != SERVICE_STOPPED {
        return Err(WinctlError::ArtifactValidation(
            "stop the service before updating its executable".into(),
        ));
    }
    if unsafe {
        ChangeServiceConfigW(
            handle.0,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            value.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn managed_command_retains_public_bundle_and_rejects_ambiguous_paths() {
        let client = std::path::Path::new(r"C:\ProgramData\AEGIS\bin\aegis-client.exe");
        let config = std::path::Path::new(r"C:\ProgramData\AEGIS\config\aegis.toml");
        let bundle = std::path::Path::new(r"C:\ProgramData\AEGIS\config\device-bundle");
        let command = command_line(client, config, Some(bundle)).unwrap();
        assert!(command.contains(" --device-online-bundle "));
        assert!(command.ends_with(" --windows-service"));
        assert!(!command_line(client, config, None)
            .unwrap()
            .contains("device-online-bundle"));
        assert!(command_line(client, config, Some(std::path::Path::new("relative"))).is_err());
        assert!(command_line(client, config, Some(std::path::Path::new("C:\\bad\"path"))).is_err());
    }

    #[test]
    fn ownership_accepts_extended_paths_but_rejects_other_executables() {
        let directory = tempfile::tempdir().unwrap();
        let binary = directory.path().join("test client.exe");
        let other = directory.path().join("other.exe");
        std::fs::write(&binary, b"fixture").unwrap();
        std::fs::write(&other, b"fixture").unwrap();
        let plain = format!(
            "\"{}\" --config fixture --windows-service",
            binary.display()
        );
        let extended = format!(
            "\"{}\" --config fixture --windows-service",
            binary.canonicalize().unwrap().display()
        );
        assert!(command_owns_binary(&plain, &binary.canonicalize().unwrap()).unwrap());
        assert!(command_owns_binary(&extended, &binary).unwrap());
        assert!(!command_owns_binary(&plain, &other).unwrap());
        assert!(
            !command_owns_binary(&format!("{} --config fixture", binary.display()), &binary)
                .unwrap()
        );
        assert!(!command_owns_binary("\"relative.exe\" --config fixture", &binary).unwrap());
        assert!(!command_owns_binary(
            &format!("\"{}\".other --config fixture", binary.display()),
            &binary
        )
        .unwrap());
    }

    #[test]
    #[ignore = "requires administrator and AEGIS_SCM_TEST_CLIENT pointing to the current built client"]
    fn native_scm_start_stop_restart_and_failed_initialization() {
        assert!(
            crate::is_elevated(),
            "native SCM test requires administrator"
        );
        let client_source = std::env::var_os("AEGIS_SCM_TEST_CLIENT").expect("current client path");
        // LocalService can traverse ProgramData; a user's TEMP ancestry can
        // legitimately deny metadata access and must not be weakened for a test.
        let temp = tempfile::tempdir_in(std::env::var_os("ProgramData").unwrap()).unwrap();
        let root = temp.path().join("service");
        aegis_core::windows_file::create_private_directory(&root, true, false).unwrap();
        aegis_core::windows_file::create_private_directory(&root.join("state"), true, true)
            .unwrap();
        let client = root.join("aegis-client.exe");
        aegis_core::windows_file::write_private_new(
            &client,
            &std::fs::read(client_source).unwrap(),
            true,
        )
        .unwrap();
        let config = root.join("aegis.toml");
        let mut settings = aegis_core::Settings {
            mode: aegis_core::Mode::Relay,
            ..Default::default()
        };
        settings.ingress.primary = aegis_core::IngressPrimary::Socks5;
        settings.ingress.allow_fallback = false;
        settings.ingress.wide.enabled = false;
        settings.socks.listen = "127.0.0.1:0".parse().unwrap();
        settings.direct.state_path = root.join("state/brain.json");
        settings.relay.server = "127.0.0.1:9".into();
        settings.relay.server_name = "fixture.test".into();
        settings.relay.auth_token =
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into();
        settings.relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
        aegis_core::windows_file::write_private_new(
            &config,
            toml::to_string(&settings).unwrap().as_bytes(),
            true,
        )
        .unwrap();
        let name = format!("AEGIS-Development-Test-{}", std::process::id());
        let foreground = std::process::Command::new(&client)
            .arg("--config")
            .arg(&config)
            .args(["--ingress-preflight", "--json"])
            .arg("--diagnostic-logs")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(
            foreground.status.success(),
            "synthetic foreground fixture: {}",
            String::from_utf8_lossy(&foreground.stderr)
        );
        assert_eq!(query(&name).unwrap()["exists"], false);
        struct Cleanup(String);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = run(ServiceCommand::Uninstall(crate::ServiceNameArg {
                    service_name: self.0.clone(),
                }));
            }
        }
        let _cleanup = Cleanup(name.clone());
        run(ServiceCommand::Install(crate::ServiceInstallArgs {
            service_name: name.clone(),
            display_name: "AEGIS isolated development test".into(),
            bin_path: format!(
                "\"{}\" --config \"{}\" --windows-service",
                client.display(),
                config.display()
            ),
            start: "demand".into(),
            system_tunnel: false,
        }))
        .unwrap();
        for _ in 0..2 {
            run(ServiceCommand::Start(crate::ServiceNameArg {
                service_name: name.clone(),
            }))
            .unwrap();
            let observed = query(&name).unwrap();
            assert_eq!(observed["state"], "RUNNING");
            assert!(observed["process_id"].as_u64().unwrap() > 0);
            run(ServiceCommand::Stop(crate::ServiceNameArg {
                service_name: name.clone(),
            }))
            .unwrap();
            assert_eq!(query(&name).unwrap()["state"], "STOPPED");
        }
        std::fs::remove_file(&config).unwrap();
        aegis_core::windows_file::write_private_new(
            &config,
            b"broken = 'SYNTHETIC_SECRET_UNTERMINATED",
            true,
        )
        .unwrap();
        assert!(run(ServiceCommand::Start(crate::ServiceNameArg {
            service_name: name.clone()
        }))
        .is_err());
        assert_eq!(query(&name).unwrap()["state"], "STOPPED");
        assert_eq!(query(&name).unwrap()["service_exit_code"], 10);
        run(ServiceCommand::Uninstall(crate::ServiceNameArg {
            service_name: name.clone(),
        }))
        .unwrap();
        assert_eq!(query(&name).unwrap()["exists"], false);
    }
    #[test]
    fn rejects_nul_before_scm() {
        assert!(wide("Aegis\0Other").is_err());
    }
    #[test]
    fn numeric_states_do_not_depend_on_windows_language() {
        assert_eq!(state_name(4), "RUNNING");
        assert_eq!(state_name(1), "STOPPED");
        assert_eq!(state_name(3), "STOP_PENDING");
    }
    #[test]
    fn nonexistent_service_is_explicit() {
        let result = query("AEGIS-Test-Nonexistent-8A1946C1").unwrap();
        assert_eq!(result["exists"], false);
    }
}
