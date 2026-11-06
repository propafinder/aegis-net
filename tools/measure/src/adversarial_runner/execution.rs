use std::path::Path;

pub(super) struct LiveCommandResult {
    pub(super) timed_out: bool,
    pub(super) returncode: Option<i32>,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr: Vec<u8>,
}

#[cfg(unix)]
mod unix {
    use super::LiveCommandResult;
    use std::{
        io::{self, Read},
        os::{fd::AsRawFd, unix::process::CommandExt},
        path::Path,
        process::{Child, Command, ExitStatus, Stdio},
        thread,
        time::{Duration, Instant},
    };

    const CAPTURE_LIMIT: usize = 64 * 1024;
    const READ_BURST: usize = 16;
    const CLEANUP_LIMIT: Duration = Duration::from_millis(250);
    const TRUNCATED: &[u8] = b"\n[diagnostic output truncated]\n";

    struct Pipe<R> {
        reader: Option<R>,
        captured: Vec<u8>,
        truncated: bool,
    }

    impl<R: Read + AsRawFd> Pipe<R> {
        fn new(reader: R) -> io::Result<Self> {
            let fd = reader.as_raw_fd();
            // SAFETY: fd belongs to the live reader; neither call transfers it.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(Self {
                reader: Some(reader),
                captured: Vec::new(),
                truncated: false,
            })
        }

        fn drain(&mut self) -> io::Result<()> {
            let Some(reader) = self.reader.as_mut() else {
                return Ok(());
            };
            let mut buffer = [0; 8192];
            // A continuously ready stream cannot monopolize deadline checks or
            // prevent the other stream from being drained.
            for _ in 0..READ_BURST {
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        self.reader = None;
                        break;
                    }
                    Ok(count) => {
                        let keep = count.min(CAPTURE_LIMIT - self.captured.len());
                        self.captured.extend_from_slice(&buffer[..keep]);
                        self.truncated |= keep < count;
                    }
                    Err(err) if err.kind() == io::ErrorKind::WouldBlock => break,
                    Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                    Err(err) => {
                        self.reader = None;
                        return Err(err);
                    }
                }
            }
            Ok(())
        }

        fn closed(&self) -> bool {
            self.reader.is_none()
        }

        fn finish(mut self) -> Vec<u8> {
            if self.truncated {
                self.captured.truncate(CAPTURE_LIMIT - TRUNCATED.len());
                self.captured.splice(0..0, TRUNCATED.iter().copied());
            }
            self.captured
        }
    }

    struct OwnedChild {
        child: Child,
        group_signalled: bool,
    }

    impl OwnedChild {
        fn exited_unreaped(&mut self) -> io::Result<bool> {
            // SAFETY: zero is valid initialization for siginfo_t, and waitid
            // writes only that object. WNOWAIT retains the owned leader PID,
            // so it cannot be reused before group cleanup signals it.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let rc = unsafe {
                libc::waitid(
                    libc::P_PID,
                    self.child.id() as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            };
            if rc < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    return Ok(false);
                }
                if err.raw_os_error() == Some(libc::ECHILD) {
                    // An external reaper would invalidate the reserved identity.
                    // Refuse a group signal once we no longer own its leader.
                    self.group_signalled = true;
                }
                return Err(err);
            }
            Ok(info.si_signo != 0)
        }

        fn stop_group(&mut self) -> io::Result<()> {
            if self.group_signalled {
                return Ok(());
            }
            self.group_signalled = true;
            // SAFETY: process_group(0) created this group, its leader has not
            // been reaped, and only this owner signals it. This is group
            // ownership, not containment of descendants that leave the group.
            let rc = unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
            if rc < 0 {
                let err = io::Error::last_os_error();
                #[cfg(target_os = "macos")]
                if err.raw_os_error() == Some(libc::EPERM) && self.only_exited_leader() {
                    return Ok(());
                }
                if err.raw_os_error() != Some(libc::ESRCH) {
                    let _ = self.child.kill();
                    return Err(err);
                }
            }
            Ok(())
        }

        #[cfg(target_os = "macos")]
        fn only_exited_leader(&mut self) -> bool {
            if !matches!(self.exited_unreaped(), Ok(true)) {
                return false;
            }
            // Darwin can return EPERM for a group whose sole member is its
            // unreaped zombie leader. Verify that exact case rather than
            // suppressing a permission failure for live descendants. A second
            // slot detects any other member without an unbounded PID list.
            let mut members = [0 as libc::pid_t; 2];
            // SAFETY: __error returns this thread's errno; the group query
            // writes at most the size of the initialized two-PID buffer.
            let (count, errno) = unsafe {
                *libc::__error() = 0;
                let count = libc::proc_listpgrppids(
                    self.child.id() as libc::pid_t,
                    members.as_mut_ptr().cast(),
                    std::mem::size_of_val(&members) as libc::c_int,
                );
                (count, *libc::__error())
            };
            errno == 0
                && (count == 0 || (count == 1 && members[0] == self.child.id() as libc::pid_t))
        }
    }

    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.stop_group();
            // Never turn unwinding or an early setup error into a blocking wait.
            let _ = self.child.try_wait();
        }
    }

    fn error_result(message: String) -> LiveCommandResult {
        LiveCommandResult {
            timed_out: false,
            returncode: Some(127),
            stdout: Vec::new(),
            stderr: message.into_bytes(),
        }
    }

    fn remember_error(error: &mut Option<String>, phase: &str, err: io::Error) {
        if error.is_none() {
            *error = Some(format!("subprocess {phase}: {err}"));
        }
    }

    fn cleanup<R: Read + AsRawFd, S: Read + AsRawFd>(
        owner: &mut OwnedChild,
        stdout: &mut Pipe<R>,
        stderr: &mut Pipe<S>,
        error: &mut Option<String>,
    ) -> Option<ExitStatus> {
        if let Err(err) = owner.stop_group() {
            remember_error(error, "group cleanup", err);
        }
        let deadline = Instant::now() + CLEANUP_LIMIT;
        let mut status = None;
        loop {
            if let Err(err) = stdout.drain() {
                remember_error(error, "stdout drain", err);
            }
            if let Err(err) = stderr.drain() {
                remember_error(error, "stderr drain", err);
            }
            if status.is_none() {
                match owner.child.try_wait() {
                    Ok(value) => status = value,
                    Err(err) => {
                        remember_error(error, "exit observation", err);
                        break;
                    }
                }
            }
            if status.is_some() && stdout.closed() && stderr.closed() {
                break;
            }
            if Instant::now() >= deadline {
                if status.is_none() && error.is_none() {
                    *error =
                        Some("subprocess cleanup: child exit not observed within 250 ms".into());
                }
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        status
    }

    pub(super) fn run(root: &Path, command: &str, timeout_seconds: f64) -> LiveCommandResult {
        if !timeout_seconds.is_finite() {
            return error_result("subprocess timeout must be finite".into());
        }
        let Ok(timeout) = Duration::try_from_secs_f64(timeout_seconds.max(0.001)) else {
            return error_result("subprocess timeout is out of range".into());
        };
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return error_result("subprocess deadline is out of range".into());
        };
        let child = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(root)
            .process_group(0)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn();
        let mut owner = match child {
            Ok(child) => OwnedChild {
                child,
                group_signalled: false,
            },
            Err(err) => return error_result(format!("subprocess spawn: {err}")),
        };
        let stdout = Pipe::new(owner.child.stdout.take().expect("piped stdout"));
        let stderr = Pipe::new(owner.child.stderr.take().expect("piped stderr"));
        let (mut stdout, mut stderr) = match (stdout, stderr) {
            (Ok(stdout), Ok(stderr)) => (stdout, stderr),
            (stdout, stderr) => {
                let err = stdout
                    .err()
                    .or_else(|| stderr.err())
                    .expect("pipe setup error");
                let _ = owner.stop_group();
                let until = Instant::now() + CLEANUP_LIMIT;
                while Instant::now() < until {
                    if !matches!(owner.child.try_wait(), Ok(None)) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(1));
                }
                return error_result(format!("subprocess pipe setup: {err}"));
            }
        };
        let mut timed_out = false;
        let mut error = None;
        loop {
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            if let Err(err) = stdout.drain() {
                remember_error(&mut error, "stdout drain", err);
                break;
            }
            if let Err(err) = stderr.drain() {
                remember_error(&mut error, "stderr drain", err);
                break;
            }
            let exited = match owner.exited_unreaped() {
                Ok(value) => value,
                Err(err) => {
                    remember_error(&mut error, "exit observation", err);
                    break;
                }
            };
            if Instant::now() >= deadline {
                timed_out = true;
                break;
            }
            if exited && stdout.closed() && stderr.closed() {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        let status = cleanup(&mut owner, &mut stdout, &mut stderr, &mut error);
        let stdout = stdout.finish();
        let mut stderr = stderr.finish();
        if let Some(error) = &error {
            let diagnostic = format!("\n[{error}]\n");
            stderr.truncate(CAPTURE_LIMIT.saturating_sub(diagnostic.len()));
            stderr.splice(0..0, diagnostic.bytes());
        }
        LiveCommandResult {
            timed_out,
            returncode: if timed_out {
                None
            } else if error.is_some() {
                Some(127)
            } else {
                status.and_then(|status| status.code())
            },
            stdout,
            stderr,
        }
    }
}

#[cfg(unix)]
pub(super) fn run_live_command(
    root: &Path,
    live_command: &str,
    timeout_seconds: f64,
) -> LiveCommandResult {
    unix::run(root, live_command, timeout_seconds)
}

#[cfg(not(unix))]
pub(super) fn run_live_command(
    _root: &Path,
    _live_command: &str,
    _timeout_seconds: f64,
) -> LiveCommandResult {
    LiveCommandResult {
        timed_out: false,
        returncode: Some(127),
        stdout: Vec::new(),
        stderr: b"owned subprocess execution is unavailable on this platform".to_vec(),
    }
}

pub(super) fn trim_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_string()
}

pub(super) fn excerpt(bytes: &[u8]) -> String {
    let text = trim_output(bytes);
    text.chars().take(512).collect()
}

#[cfg(all(test, unix))]
#[path = "execution_tests.rs"]
mod tests;
