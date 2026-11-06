//! Private installer inputs. No URL or credential is a child argument or an
//! environment entry. Filesystem operations retain their synchronous I/O limits.
#[cfg(unix)]
use std::io::Write;
use std::{
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;

pub const URL_LIMIT: usize = 8192;
pub const TOKEN_LIMIT: usize = 4096;

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "private installer input rejected",
    )
}

fn checked_text(bytes: &[u8], limit: usize, trailing_lf: bool) -> io::Result<Zeroizing<String>> {
    if bytes.len() > limit {
        return Err(refused());
    }
    let bytes = if trailing_lf {
        bytes.strip_suffix(b"\n").unwrap_or(bytes)
    } else {
        bytes
    };
    let text = std::str::from_utf8(bytes).map_err(|_| refused())?;
    if text.is_empty() || text.chars().any(char::is_control) {
        return Err(refused());
    }
    Ok(Zeroizing::new(text.to_owned()))
}

#[cfg(unix)]
fn private_file(path: &Path, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    if !path.is_absolute() {
        return Err(refused());
    }
    crate::secret_file::trusted_read_parent(path).map_err(|_| refused())?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| refused())?;
    let metadata = file.metadata().map_err(|_| refused())?;
    // SAFETY: geteuid reads identity and does not transfer ownership.
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || ![0, uid].contains(&metadata.uid())
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > limit as u64
    {
        return Err(refused());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    if bytes.len() > limit {
        return Err(refused());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn private_file(_: &Path, _: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "private installer inputs require Unix custody",
    ))
}

pub fn read_url(path: &Path) -> io::Result<Zeroizing<String>> {
    checked_text(&private_file(path, URL_LIMIT)?, URL_LIMIT, true)
}
pub fn read_token(path: &Path) -> io::Result<Zeroizing<String>> {
    checked_text(&private_file(path, TOKEN_LIMIT)?, TOKEN_LIMIT, false)
}
pub fn token_from_stdin(reader: impl Read) -> io::Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(TOKEN_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    checked_text(&bytes, TOKEN_LIMIT, false)
}
pub fn write_url_from_stdin(path: &Path, reader: impl Read) -> io::Result<()> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take(URL_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    let url = checked_text(&bytes, URL_LIMIT, true)?;
    write_url(path, &url)
}
pub fn write_url(path: &Path, text: &str) -> io::Result<()> {
    let text = checked_text(text.as_bytes(), URL_LIMIT, true)?;
    crate::secret_file::write_private_new(path, text.as_bytes()).map_err(|_| {
        io::Error::other("private access URL output failed; issuance may have committed")
    })
}

/// No Debug implementation: the path's contents remain an owned private input.
pub struct Download<'a> {
    pub input: &'a Path,
    pub output: &'a Path,
    pub connect_seconds: u64,
    pub total_seconds: u64,
    pub pin: Option<&'a str>,
    pub insecure: bool,
    pub local_only: bool,
    pub allow_local_path: bool,
    /// The verified client CLI owns the internal local-copy worker.
    pub local_worker: &'a Path,
}

#[derive(Debug)]
pub struct TransferError {
    pub code: i32,
    pub reason: &'static str,
}
impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "download: stage=transfer reason={} exit_code={}",
            self.reason, self.code
        )
    }
}
impl std::error::Error for TransferError {}

pub fn fetch(request: Download<'_>) -> Result<(), TransferError> {
    #[cfg(unix)]
    {
        unix::fetch(request)
    }
    #[cfg(not(unix))]
    {
        let _ = request;
        Err(TransferError {
            code: 2,
            reason: "unsupported_private_custody",
        })
    }
}

/// Internal CLI worker. Its parent owns the whole transfer deadline. Only a
/// private, finite regular stdin descriptor and the fresh private output inode
/// are admitted; a general pipe/interactive input is refused before a read.
#[cfg(unix)]
pub fn copy_local_from_stdin(output: &Path) -> io::Result<()> {
    use std::os::unix::{
        ffi::OsStringExt,
        fs::{MetadataExt, OpenOptionsExt},
        io::FromRawFd,
    };
    // SAFETY: duplication gives this worker one independently owned reference
    // to stdin; dropping it does not close the caller's original descriptor.
    let descriptor = unsafe { libc::fcntl(libc::STDIN_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
    if descriptor < 0 {
        return Err(refused());
    }
    let input = unsafe { std::fs::File::from_raw_fd(descriptor) };
    let metadata = input.metadata().map_err(|_| refused())?;
    let uid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() > 1
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() > URL_LIMIT as u64
    {
        return Err(refused());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    input
        .take(URL_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| refused())?;
    if bytes.is_empty() || bytes.len() > URL_LIMIT || bytes.contains(&0) {
        return Err(refused());
    }
    let source_path = std::ffi::OsString::from_vec(bytes.to_vec());
    let mut source = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(source_path)
        .map_err(|_| refused())?;
    if !source.metadata().map_err(|_| refused())?.is_file() {
        return Err(refused());
    }
    crate::secret_file::trusted_parent(output).map_err(|_| refused())?;
    let mut destination = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(output)
        .map_err(|_| refused())?;
    let metadata = destination.metadata().map_err(|_| refused())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != uid
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(refused());
    }
    // The inode is checked before truncation; the parent never supplies an
    // existing installed output and retains this same fresh inode reference.
    destination.set_len(0).map_err(|_| refused())?;
    io::copy(&mut source, &mut destination).map_err(|_| refused())?;
    destination.sync_all().map_err(|_| refused())
}
#[cfg(not(unix))]
pub fn copy_local_from_stdin(_: &Path) -> io::Result<()> {
    Err(refused())
}

#[cfg(unix)]
mod unix {
    use super::*;
    use std::{
        os::unix::process::CommandExt,
        process::{Child, Command, ExitStatus, Stdio},
        sync::{
            atomic::{AtomicI32, Ordering},
            Mutex,
        },
        thread,
        time::{Duration, Instant},
    };

    const CLEANUP: Duration = Duration::from_secs(4);
    static SIGNAL: AtomicI32 = AtomicI32::new(0);
    // The CLI owns one transfer; a concurrent in-process caller refuses rather
    // than installing handlers over another owner. Tests must use fresh children.
    static SIGNAL_OWNER: Mutex<()> = Mutex::new(());
    extern "C" fn received(signal: libc::c_int) {
        SIGNAL.store(signal, Ordering::Relaxed);
    }
    struct Signals {
        _owner: std::sync::MutexGuard<'static, ()>,
        interrupt: libc::sigaction,
        terminate: libc::sigaction,
    }
    impl Signals {
        fn new() -> io::Result<Self> {
            let owner = SIGNAL_OWNER.try_lock().map_err(|_| refused())?;
            // Do not inherit automatic reaping or an unknown handler which can
            // consume the reserved child before the last owned group signal.
            // This CLI requires exclusive child ownership; it never changes
            // SIGCHLD disposition or grants an in-process reaper authority.
            let mut children: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut children) } != 0
                || children.sa_sigaction != libc::SIG_DFL
                || children.sa_flags & libc::SA_NOCLDWAIT != 0
            {
                return Err(refused());
            }
            SIGNAL.store(0, Ordering::Relaxed);
            // SAFETY: initialized sigaction objects and correct handler ABI;
            // the mutex reserves restoration for this one transfer owner.
            unsafe {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = received as *const () as usize;
                libc::sigemptyset(&mut action.sa_mask);
                let mut interrupt = std::mem::zeroed();
                let mut terminate = std::mem::zeroed();
                if libc::sigaction(libc::SIGINT, &action, &mut interrupt) != 0 {
                    return Err(refused());
                }
                if libc::sigaction(libc::SIGTERM, &action, &mut terminate) != 0 {
                    libc::sigaction(libc::SIGINT, &interrupt, std::ptr::null_mut());
                    return Err(refused());
                }
                Ok(Self {
                    _owner: owner,
                    interrupt,
                    terminate,
                })
            }
        }
    }
    impl Drop for Signals {
        fn drop(&mut self) {
            // SAFETY: exact earlier process handlers, held under the same lease.
            unsafe {
                libc::sigaction(libc::SIGINT, &self.interrupt, std::ptr::null_mut());
                libc::sigaction(libc::SIGTERM, &self.terminate, std::ptr::null_mut());
            }
        }
    }
    fn failure(code: i32, reason: &'static str) -> TransferError {
        TransferError { code, reason }
    }
    fn cancellation() -> Result<(), TransferError> {
        let signal = SIGNAL.load(Ordering::Relaxed);
        if signal != 0 {
            return Err(failure(128 + signal, "cancelled"));
        }
        Ok(())
    }
    fn check(deadline: Instant) -> Result<(), TransferError> {
        cancellation()?;
        if Instant::now() >= deadline {
            return Err(failure(124, "total_deadline"));
        }
        Ok(())
    }

    struct OwnedChild {
        child: Child,
        reserved: bool,
        finished: bool,
    }
    impl OwnedChild {
        fn exited(&mut self) -> io::Result<bool> {
            // SAFETY: WNOWAIT observes only this still-owned child and keeps its
            // identity reserved until the last group signal and final reap.
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
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ECHILD) {
                    self.reserved = false;
                }
                if e.kind() == io::ErrorKind::Interrupted {
                    return Ok(false);
                }
                return Err(e);
            }
            Ok(info.si_signo != 0)
        }
        #[cfg(target_os = "macos")]
        fn zombie_only(&mut self) -> bool {
            if !matches!(self.exited(), Ok(true)) {
                return false;
            }
            let mut pids = [0 as libc::pid_t; 2];
            // SAFETY: the bounded two-slot query can detect a second group
            // member, and the leader is still retained by WNOWAIT.
            let (count, errno) = unsafe {
                *libc::__error() = 0;
                let count = libc::proc_listpgrppids(
                    self.child.id() as libc::pid_t,
                    pids.as_mut_ptr().cast(),
                    std::mem::size_of_val(&pids) as libc::c_int,
                );
                (count, *libc::__error())
            };
            errno == 0 && (count == 0 || (count == 1 && pids[0] == self.child.id() as libc::pid_t))
        }
        fn signal(&mut self, signal: i32) -> io::Result<()> {
            if !self.reserved {
                return Err(refused());
            }
            // SAFETY: process_group(0) creates the owned group before exec;
            // WNOWAIT prevents PID reuse until both signals have completed.
            if unsafe { libc::kill(-(self.child.id() as libc::pid_t), signal) } < 0 {
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ESRCH) {
                    return Ok(());
                }
                #[cfg(target_os = "macos")]
                if e.raw_os_error() == Some(libc::EPERM) && self.zombie_only() {
                    return Ok(());
                }
                return Err(e);
            }
            Ok(())
        }
        fn cleanup(&mut self) -> io::Result<ExitStatus> {
            if self.finished {
                return Err(refused());
            }
            // Enter cleanup once. Even an observation/signal failure cannot
            // cause Drop to renew this four-second attempt or signal later.
            self.finished = true;
            let deadline = Instant::now() + CLEANUP;
            let term = self.signal(libc::SIGTERM);
            let grace = Instant::now() + Duration::from_millis(100);
            let mut observation_error = None;
            while Instant::now() < grace && Instant::now() < deadline {
                match self.exited() {
                    Ok(true) => break,
                    Ok(false) => {}
                    Err(error) => {
                        observation_error = Some(error);
                        break;
                    }
                }
                thread::sleep(Duration::from_millis(5));
            }
            let kill = self.signal(libc::SIGKILL);
            // No later signals, including Drop, are legal after any reap.
            if !self.reserved {
                return Err(refused());
            }
            while Instant::now() < deadline {
                if let Some(status) = self.child.try_wait()? {
                    self.reserved = false;
                    term?;
                    kill?;
                    if let Some(error) = observation_error {
                        return Err(error);
                    }
                    return Ok(status);
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned transfer cleanup unconfirmed",
            ))
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !self.finished {
                let _ = self.cleanup();
            }
        }
    }

    fn executable(name: &str) -> Option<std::path::PathBuf> {
        use std::os::unix::fs::PermissionsExt;
        std::env::split_paths(&std::env::var_os("PATH")?)
            .map(|p| p.join(name))
            .find(|p| {
                std::fs::metadata(p)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
    }
    fn url_pin(url: &str) -> Option<&str> {
        url.split(['?', '&'])
            .filter_map(|part| part.strip_prefix("pin="))
            .find(|p| {
                p.starts_with("sha256//")
                    && p.len() > 8
                    && p.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"+/=_-".contains(&b))
            })
    }
    // Linux's old urllib file reader decoded a file URI's path; macOS's old
    // cp branch used the literal suffix and also admitted plain local paths.
    // Keep those two existing contracts explicit, without a URL in argv.
    fn local_path(
        url: &str,
        allow_plain: bool,
    ) -> Result<Option<std::path::PathBuf>, TransferError> {
        use std::os::unix::ffi::OsStringExt;
        let Some(suffix) = url.strip_prefix("file://") else {
            return Ok((allow_plain && !url.contains("://")).then(|| Path::new(url).to_owned()));
        };
        if allow_plain {
            return Ok(Some(Path::new(suffix).to_owned()));
        }
        let path = if suffix.starts_with('/') {
            suffix
        } else if let Some(path) = suffix.strip_prefix("localhost/") {
            // Keep the slash belonging to the URI's path.
            return local_path(&format!("file:///{path}"), false);
        } else {
            return Err(failure(2, "nonlocal_file_authority_refused"));
        };
        let path = path.split(['?', '#']).next().unwrap_or(path);
        let mut decoded = Vec::with_capacity(path.len());
        let bytes = path.as_bytes();
        let mut index = 0;
        while index < bytes.len() {
            let value = if bytes[index] == b'%' && index + 2 < bytes.len() {
                (bytes[index + 1] as char)
                    .to_digit(16)
                    .zip((bytes[index + 2] as char).to_digit(16))
            } else {
                None
            };
            if let Some((high, low)) = value {
                let byte = (high * 16 + low) as u8;
                if byte == 0 {
                    return Err(failure(2, "invalid_file_uri_escape"));
                }
                decoded.push(byte);
                index += 3;
            } else {
                decoded.push(bytes[index]);
                index += 1;
            }
        }
        Ok(Some(std::ffi::OsString::from_vec(decoded).into()))
    }
    pub(super) fn fetch(request: Download<'_>) -> Result<(), TransferError> {
        let origin = Instant::now();
        if !(1..=3600).contains(&request.total_seconds)
            || !(1..=request.total_seconds.min(300)).contains(&request.connect_seconds)
        {
            return Err(failure(2, "invalid_time_budget"));
        }
        let deadline = origin
            .checked_add(Duration::from_secs(request.total_seconds))
            .ok_or_else(|| failure(2, "invalid_time_budget"))?;
        let _signals = Signals::new().map_err(|_| failure(2, "signal_owner_unavailable"))?;
        let url = read_url(request.input).map_err(|_| failure(2, "private_input_rejected"))?;
        check(deadline)?;
        let local = local_path(&url, request.allow_local_path)?;
        let local_copy = local.is_some();
        let mut command: Command;
        let mut input_bytes = Zeroizing::new(Vec::new());
        let mut downloader_is_wget = false;
        if let Some(path) = local {
            use std::os::unix::ffi::OsStrExt;
            input_bytes.extend_from_slice(path.as_os_str().as_bytes());
            let mut worker = Command::new(request.local_worker);
            worker.args(["profile", "installer-secret", "copy-stdin"]);
            command = worker;
        } else {
            if request.local_only {
                return Err(failure(2, "offline_requires_local_bundle"));
            }
            if !url.starts_with("https://") {
                return Err(failure(2, "unsupported_url_scheme"));
            }
            let pin = request
                .pin
                .filter(|p| !p.is_empty())
                .or_else(|| url_pin(&url));
            if request.insecure && pin.is_none() {
                return Err(failure(2, "unpinned_insecure_refused"));
            }
            if let Some(curl) = executable("curl") {
                let mut c = Command::new(curl);
                c.args([
                    "-q",
                    "-fsSL",
                    "--http1.1",
                    "--proto",
                    "=https",
                    "--proto-redir",
                    "=https",
                    "--connect-timeout",
                    &request.connect_seconds.to_string(),
                    "--max-time",
                    &request.total_seconds.to_string(),
                    "--retry",
                    "0",
                ]);
                if let Some(pin) = pin {
                    c.args([
                        "--insecure",
                        "--pinnedpubkey",
                        &format!("sha256//{}", pin.strip_prefix("sha256//").unwrap_or(pin)),
                    ]);
                }
                c.args(["--config", "-"]);
                let quoted = Zeroizing::new(url.replace('\\', "\\\\").replace('"', "\\\""));
                input_bytes
                    .extend_from_slice(format!("url = \"{}\"\n", quoted.as_str()).as_bytes());
                command = c;
            } else if let Some(wget) = executable("wget") {
                if pin.is_some() {
                    return Err(failure(2, "spki_pin_requires_curl"));
                }
                let mut c = Command::new(wget);
                c.args([
                    "--no-config",
                    &format!("--timeout={}", request.connect_seconds),
                    "--tries=1",
                    "--max-redirect=0",
                    "--input-file=-",
                ]);
                input_bytes.extend_from_slice(url.as_bytes());
                input_bytes.push(b'\n');
                downloader_is_wget = true;
                command = c;
            } else {
                return Err(failure(2, "curl_or_wget_required"));
            }
        }
        // Private input and transport admission happen before any destination
        // entry is created. All outputs are fresh owner-private staging.
        let parent = crate::secret_file::trusted_parent(request.output)
            .map_err(|_| failure(1, "output_custody_rejected"))?;
        if std::fs::symlink_metadata(request.output).is_ok() {
            return Err(failure(1, "output_already_exists"));
        }
        let partial = tempfile::NamedTempFile::new_in(&parent)
            .map_err(|_| failure(1, "output_staging_failed"))?;
        {
            let mut input =
                tempfile::tempfile_in(&parent).map_err(|_| failure(1, "input_staging_failed"))?;
            use std::os::unix::fs::PermissionsExt;
            input
                .set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|_| failure(1, "input_staging_failed"))?;
            input
                .write_all(&input_bytes)
                .map_err(|_| failure(1, "input_staging_failed"))?;
            use std::io::{Seek, SeekFrom};
            input
                .seek(SeekFrom::Start(0))
                .map_err(|_| failure(1, "input_staging_failed"))?;
            if local_copy {
                command.arg("--output").arg(partial.path());
            } else if downloader_is_wget {
                command.arg("-qO").arg(partial.path());
            } else {
                command.arg("-o").arg(partial.path());
            }
            command
                .stdin(Stdio::from(input))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .process_group(0);
            check(deadline)?;
            let child = command.spawn().map_err(|_| failure(1, "spawn_failed"))?;
            let mut child = OwnedChild {
                child,
                reserved: true,
                finished: false,
            };
            let outcome = loop {
                if let Err(e) = check(deadline) {
                    break Err(e);
                }
                match child.exited() {
                    Ok(true) => break Ok(()),
                    Ok(false) => {}
                    Err(_) => break Err(failure(1, "exit_observation_failed")),
                }
                thread::sleep(Duration::from_millis(5));
            };
            let status = child
                .cleanup()
                .map_err(|_| failure(1, "cleanup_unconfirmed"))?;
            outcome?;
            use std::os::unix::process::ExitStatusExt;
            if !status.success() {
                return Err(failure(
                    status.code().unwrap_or(128 + status.signal().unwrap_or(0)),
                    "failed",
                ));
            }
        }
        // Transfer completion was observed against the one original deadline.
        // Cleanup has its separate allowance; it does not retroactively turn an
        // already observed successful transfer into an acquisition timeout.
        cancellation()?;
        if partial
            .as_file()
            .metadata()
            .map_err(|_| failure(1, "output_inspection_failed"))?
            .len()
            == 0
        {
            return Err(failure(65, "empty_response"));
        }
        partial
            .as_file()
            .sync_all()
            .map_err(|_| failure(1, "output_sync_failed"))?;
        partial
            .persist_noclobber(request.output)
            .map_err(|_| failure(1, "publication_failed"))?;
        crate::secret_file::sync_directory(&parent)
            .map_err(|_| failure(1, "published_directory_sync_failed"))?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "installer_secret_tests.rs"]
mod tests;
