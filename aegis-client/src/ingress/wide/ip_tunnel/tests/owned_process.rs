//! Test-only exact-child supervision. Spool files remain for failed/unknown
//! outcomes; killing a controller does not prove its separately managed service
//! or kernel policy was restored. Deadlines assume ordinary OS scheduling.
use std::{
    fs::{File, OpenOptions},
    io::{self, Read},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

const PREFIX_LIMIT: u64 = 64 * 1024;
const REAP_BUDGET: Duration = Duration::from_secs(1);
const POLL: Duration = Duration::from_millis(10);
static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub struct Outcome {
    pub reason: &'static str,
    pub status: Option<ExitStatus>,
    pub pid: u32,
    pub killed: bool,
    pub reaped: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_path: PathBuf,
    pub stderr_path: PathBuf,
    pub output_limit_exceeded: bool,
    pub output_read_failed: bool,
    pub spool_custody_confirmed: bool,
}
impl Outcome {
    pub fn success(&self) -> bool {
        self.reason == "completed"
            && self.reaped
            && self.status.is_some_and(|s| s.success())
            && !self.output_limit_exceeded
            && !self.output_read_failed
            && self.spool_custody_confirmed
    }
}

pub struct HeldCommand {
    child: Child,
    stdout: Option<File>,
    stderr: Option<File>,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
    status: Option<ExitStatus>,
    preserve_on_drop: bool,
}

fn spool(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    file.try_lock()?;
    Ok(file)
}
fn spool_custody(path: &Path) -> bool {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // A descendant inherited spool handle must prevent exclusive reopening.
        options.share_mode(0);
    }
    let Ok(file) = options.open(path) else {
        return false;
    };
    #[cfg(unix)]
    return file.try_lock().is_ok();
    #[cfg(windows)]
    {
        drop(file);
        true
    }
    #[cfg(not(any(unix, windows)))]
    false
}
fn prefix(path: &Path) -> io::Result<Vec<u8>> {
    // Independent cursor: never seek a file description shared with a still
    // running writer when exact termination/custody remains UNKNOWN.
    let file = File::open(path)?;
    let mut bytes = Vec::new();
    file.take(PREFIX_LIMIT).read_to_end(&mut bytes)?;
    Ok(bytes)
}

impl HeldCommand {
    /// Caller supplies an already private, owned directory. No shell, PID/name
    /// search, output reader thread, inherited pipe, or recursive removal.
    pub fn spawn(command: &mut Command, directory: &Path) -> io::Result<Self> {
        let label = format!(
            "owned-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        let stdout_path = directory.join(format!("{label}.stdout"));
        let stderr_path = directory.join(format!("{label}.stderr"));
        let stdout = spool(&stdout_path)?;
        let stderr = spool(&stderr_path)?;
        // Complete both fallible clones before changing Command: a second
        // clone failure must not leave the first spool attached to the caller.
        let child_stdout = Stdio::from(stdout.try_clone()?);
        let child_stderr = Stdio::from(stderr.try_clone()?);
        command.stdout(child_stdout).stderr(child_stderr);
        let child = command.spawn();
        // Command itself otherwise retains the cloned spool descriptors after
        // spawning, preventing an honest post-child custody observation.
        command.stdout(Stdio::null()).stderr(Stdio::null());
        let child = child?;
        Ok(Self {
            child,
            stdout: Some(stdout),
            stderr: Some(stderr),
            stdout_path,
            stderr_path,
            status: None,
            preserve_on_drop: false,
        })
    }

    /// Used only after the recovery child's actual ready barrier. Panic/parent
    /// loss must not terminate that independent recovery. Explicit finish still
    /// observes or terminates only this held child and never claims restoration.
    pub fn preserve_on_parent_loss(&mut self) {
        self.preserve_on_drop = true;
    }

    pub fn wait_ready_file(&mut self, ready: &Path, deadline: Instant) -> io::Result<()> {
        loop {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "ready deadline"));
            }
            self.status = self.child.try_wait()?;
            if self.status.is_some() {
                return Err(io::Error::other("owned child exited before ready"));
            }
            if let Ok(info) = std::fs::symlink_metadata(ready) {
                if !info.file_type().is_file() || info.len() > 5 {
                    return Err(io::Error::other("invalid owned ready record"));
                }
                if info.len() < 5 {
                    thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
                    continue;
                }
                if std::fs::read(ready)? != b"armed" {
                    return Err(io::Error::other("invalid owned ready content"));
                }
                self.status = self.child.try_wait()?;
                if self.status.is_none() && Instant::now() < deadline {
                    return Ok(());
                }
                return Err(io::Error::other("ready observation late or child exited"));
            }
            thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
    }

    /// Observe completion before the absolute operation deadline. If necessary,
    /// kill the held child and poll/reap for at most one additional second.
    /// Controller termination alone never proves native recovery.
    pub fn finish(mut self, deadline: Instant) -> Outcome {
        let mut reason = "deadline_exceeded";
        let mut output_limit_exceeded = false;
        let mut output_read_failed = false;
        loop {
            if Instant::now() >= deadline {
                break;
            }
            match (
                self.stdout.as_ref().unwrap().metadata(),
                self.stderr.as_ref().unwrap().metadata(),
            ) {
                (Ok(out), Ok(err)) => {
                    if out.len() > PREFIX_LIMIT || err.len() > PREFIX_LIMIT {
                        reason = "output_limit_exceeded";
                        output_limit_exceeded = true;
                        break;
                    }
                }
                _ => {
                    reason = "output_observation_unknown";
                    output_read_failed = true;
                    break;
                }
            }
            match self.child.try_wait() {
                Ok(status) => self.status = status,
                Err(_) => {
                    reason = "process_observation_unknown";
                    break;
                }
            }
            // A successful observation after the cutoff cannot pass.
            if Instant::now() >= deadline {
                break;
            }
            if self.status.is_some() {
                reason = "completed";
                break;
            }
            thread::sleep(POLL.min(deadline.saturating_duration_since(Instant::now())));
        }
        let mut killed = false;
        if self.status.is_none() {
            killed = self.child.kill().is_ok();
            let reap_deadline = Instant::now() + REAP_BUDGET;
            while Instant::now() < reap_deadline {
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.status = Some(status);
                        break;
                    }
                    Ok(None) => thread::sleep(
                        POLL.min(reap_deadline.saturating_duration_since(Instant::now())),
                    ),
                    Err(_) => break,
                }
            }
        }
        let stdout = prefix(&self.stdout_path);
        let stderr = prefix(&self.stderr_path);
        output_read_failed |= stdout.is_err() || stderr.is_err();
        output_limit_exceeded |= self
            .stdout
            .as_ref()
            .unwrap()
            .metadata()
            .and_then(|out| {
                self.stderr
                    .as_ref()
                    .unwrap()
                    .metadata()
                    .map(|err| (out, err))
            })
            .map_or(true, |(out, err)| {
                out.len() > PREFIX_LIMIT || err.len() > PREFIX_LIMIT
            });
        drop(self.stdout.take());
        drop(self.stderr.take());
        let spool_custody_confirmed = self.status.is_some()
            && spool_custody(&self.stdout_path)
            && spool_custody(&self.stderr_path);
        Outcome {
            reason,
            status: self.status,
            pid: self.child.id(),
            killed,
            reaped: self.status.is_some(),
            stdout: stdout.unwrap_or_default(),
            stderr: stderr.unwrap_or_default(),
            stdout_path: self.stdout_path.clone(),
            stderr_path: self.stderr_path.clone(),
            output_limit_exceeded,
            output_read_failed,
            spool_custody_confirmed,
        }
    }
}
impl Drop for HeldCommand {
    fn drop(&mut self) {
        if self.status.is_none() && !self.preserve_on_drop {
            // Exceptional caller loss: best-effort exact kill only. No unbounded
            // wait, no claim reaped/restored, no spool deletion on UNKNOWN.
            let _ = self.child.kill();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "aegis-owned-process-{}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            let builder = {
                use std::os::unix::fs::DirBuilderExt;
                let mut builder = builder;
                builder.mode(0o700);
                builder
            };
            builder.create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            if thread::panicking() {
                eprintln!(
                    "failed owned-process fixture retained: {}",
                    self.0.display()
                );
                return;
            }
            // Only this exclusively created ordinary fixture directory.
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn child(mode: &str, directory: &Directory) -> HeldCommand {
        let mut command = Command::new(std::env::current_exe().unwrap());
        let fixture = format!(
            "{}::fixture_child",
            module_path!().split_once("::").unwrap().1
        );
        command
            .args(["--exact", &fixture, "--ignored", "--nocapture"])
            .env("AEGIS_OWNED_CHILD_MODE", mode)
            .env("AEGIS_OWNED_CHILD_ROOT", &directory.0)
            .stdin(Stdio::null());
        HeldCommand::spawn(&mut command, &directory.0).unwrap()
    }
    fn ready(child: &mut HeldCommand, directory: &Directory) {
        child
            .wait_ready_file(
                &directory.0.join("ready"),
                Instant::now() + Duration::from_secs(2),
            )
            .unwrap();
    }

    #[test]
    #[ignore = "ordinary owned child fixture; never native Windows controls"]
    fn fixture_child() {
        let root = PathBuf::from(std::env::var_os("AEGIS_OWNED_CHILD_ROOT").unwrap());
        let mode = std::env::var("AEGIS_OWNED_CHILD_MODE").unwrap();
        print!("actual-prefix");
        eprint!("actual-stderr-prefix");
        std::io::stdout().flush().unwrap();
        std::io::stderr().flush().unwrap();
        if mode == "success" {
            return;
        }
        if mode == "early_error" {
            std::process::exit(7);
        }
        if mode == "preserving_parent" {
            let fixture = format!(
                "{}::fixture_child",
                module_path!().split_once("::").unwrap().1
            );
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", &fixture, "--ignored", "--nocapture"])
                .env("AEGIS_OWNED_CHILD_MODE", "delayed_recovery")
                .stdin(Stdio::null());
            let mut guardian = HeldCommand::spawn(&mut command, &root).unwrap();
            guardian
                .wait_ready_file(
                    &root.join("guardian-ready"),
                    Instant::now() + Duration::from_secs(2),
                )
                .unwrap();
            std::fs::write(
                root.join("guardian-paths"),
                format!(
                    "{}\n{}\n",
                    guardian.stdout_path.display(),
                    guardian.stderr_path.display()
                ),
            )
            .unwrap();
            guardian.preserve_on_parent_loss();
            drop(guardian);
            return;
        }
        if mode == "delayed_recovery" {
            std::fs::write(root.join("guardian-ready"), b"armed").unwrap();
            thread::sleep(Duration::from_millis(200));
            std::fs::write(root.join("recovery-done"), b"ordinary-fixture-only").unwrap();
            std::process::exit(0);
        }
        if mode == "descendant" {
            let fixture = format!(
                "{}::fixture_child",
                module_path!().split_once("::").unwrap().1
            );
            let _descendant = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &fixture, "--ignored", "--nocapture"])
                .env("AEGIS_OWNED_CHILD_MODE", "descendant_writer")
                .stdin(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while !root.join("writer-ready").exists() {
                assert!(Instant::now() < deadline);
                thread::sleep(POLL);
            }
            std::process::exit(0);
        }
        if mode == "descendant_writer" {
            std::fs::write(root.join("writer-ready"), b"armed").unwrap();
            thread::sleep(Duration::from_millis(350));
            std::process::exit(0);
        }
        if mode == "oversized" {
            std::io::stdout()
                .write_all(&vec![b'x'; PREFIX_LIMIT as usize + 1])
                .unwrap();
            std::io::stdout().flush().unwrap();
        }
        std::fs::write(root.join("ready"), b"armed").unwrap();
        // A lost fixture parent cannot leave an unlimited ordinary child.
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if mode == "spectator" {
                if let Ok(value) = std::fs::read(root.join("request")) {
                    std::fs::write(root.join("reply"), value).unwrap();
                }
            }
            thread::sleep(POLL);
        }
        std::process::exit(80);
    }

    #[test]
    fn actual_success_and_error_are_distinct() {
        for (mode, succeeds) in [("success", true), ("early_error", false)] {
            let directory = Directory::new();
            let outcome = child(mode, &directory).finish(Instant::now() + Duration::from_secs(2));
            assert_eq!(outcome.success(), succeeds);
            assert!(outcome.reaped);
            assert!(outcome.stdout.windows(13).any(|s| s == b"actual-prefix"));
            assert!(outcome.stderr.starts_with(b"actual-stderr-prefix"));
            if !succeeds {
                assert_eq!(outcome.status.unwrap().code(), Some(7));
            }
        }
    }

    #[test]
    fn actual_success_closes_parent_stdio_clones_with_command_still_alive() {
        let directory = Directory::new();
        let fixture = format!(
            "{}::fixture_child",
            module_path!().split_once("::").unwrap().1
        );
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &fixture, "--ignored", "--nocapture"])
            .env("AEGIS_OWNED_CHILD_MODE", "success")
            .env("AEGIS_OWNED_CHILD_ROOT", &directory.0)
            .stdin(Stdio::null());
        let process = HeldCommand::spawn(&mut command, &directory.0).unwrap();
        let outcome = process.finish(Instant::now() + Duration::from_secs(2));
        assert!(outcome.success() && outcome.spool_custody_confirmed && outcome.reaped);
        // Command is intentionally alive across the complete custody observation.
        drop(command);
    }

    #[test]
    fn actual_ready_hang_timeout_retains_both_prefixes_and_reaps() {
        let directory = Directory::new();
        let mut process = child("hang", &directory);
        ready(&mut process, &directory);
        let outcome = process.finish(Instant::now() + Duration::from_millis(80));
        assert_eq!(outcome.reason, "deadline_exceeded");
        assert!(!outcome.success());
        assert!(outcome.killed && outcome.reaped);
        assert!(outcome.stdout.windows(13).any(|s| s == b"actual-prefix"));
        assert!(outcome.stderr.starts_with(b"actual-stderr-prefix"));
        assert!(outcome.stdout_path.exists() && outcome.stderr_path.exists());
    }

    #[test]
    fn actual_oversized_stdout_is_refused_and_prefix_bounded() {
        let directory = Directory::new();
        let mut process = child("oversized", &directory);
        ready(&mut process, &directory);
        let outcome = process.finish(Instant::now() + Duration::from_secs(1));
        assert!(outcome.output_limit_exceeded && !outcome.success());
        assert!(outcome.killed && outcome.reaped);
        assert_eq!(outcome.stdout.len(), PREFIX_LIMIT as usize);
    }

    #[test]
    fn expired_absolute_deadline_never_accepts_late_exit() {
        let directory = Directory::new();
        let mut process = child("hang", &directory);
        ready(&mut process, &directory);
        let outcome = process.finish(Instant::now());
        assert_eq!(outcome.reason, "deadline_exceeded");
        assert!(!outcome.success() && outcome.reaped);
    }

    #[test]
    fn actual_descendant_held_spool_refuses_success_without_foreign_kill() {
        let directory = Directory::new();
        let outcome =
            child("descendant", &directory).finish(Instant::now() + Duration::from_secs(2));
        assert!(outcome.reaped && outcome.status.unwrap().success());
        assert!(!outcome.spool_custody_confirmed && !outcome.success());
        assert!(!outcome.killed);
        // The independently finite fixture exits itself; no descendant search
        // or kill is used. Observe actual spool release before fixture removal.
        let deadline = Instant::now() + Duration::from_secs(1);
        while !spool_custody(&outcome.stdout_path) || !spool_custody(&outcome.stderr_path) {
            assert!(Instant::now() < deadline);
            thread::sleep(POLL);
        }
    }

    #[test]
    fn actual_parent_exit_preserves_prearmed_ordinary_recovery_child() {
        let directory = Directory::new();
        let parent =
            child("preserving_parent", &directory).finish(Instant::now() + Duration::from_secs(2));
        // A preserved live guardian can still hold ancestor spool handles on
        // Windows. This fixture proves parent termination separately, then
        // requires all four actual spool closures after recovery. It must not
        // weaken HeldCommand::success() for any promoting/native caller.
        assert!(
            parent.reason == "completed"
                && parent.status.is_some_and(|status| status.code() == Some(0))
                && parent.reaped
                && !parent.killed
                && !parent.output_limit_exceeded
                && !parent.output_read_failed,
            "parent termination refused: reason={} status={:?} pid={} reaped={} killed={} output_limit={} output_read_failed={} initial_spool_custody={} stdout_bytes={} stderr_bytes={}",
            parent.reason, parent.status, parent.pid, parent.reaped, parent.killed,
            parent.output_limit_exceeded, parent.output_read_failed,
            parent.spool_custody_confirmed, parent.stdout.len(), parent.stderr.len()
        );
        assert_eq!(
            std::fs::read(directory.0.join("guardian-ready")).unwrap(),
            b"armed"
        );
        let paths = std::fs::read_to_string(directory.0.join("guardian-paths")).unwrap();
        let mut paths: Vec<_> = paths.lines().map(PathBuf::from).collect();
        assert_eq!(paths.len(), 2);
        paths.extend([parent.stdout_path.clone(), parent.stderr_path.clone()]);
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let recorded = std::fs::read(directory.0.join("recovery-done"))
                .ok()
                .is_some_and(|value| value == b"ordinary-fixture-only");
            if recorded && paths.iter().all(|p| spool_custody(p)) && Instant::now() < deadline {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "preserved recovery/all four spool closures not confirmed within original1s after parent exit; parent_initial_custody={} recorded={} current_custody={:?}",
                parent.spool_custody_confirmed, recorded,
                paths.iter().map(|p| spool_custody(p)).collect::<Vec<_>>()
            );
            thread::sleep(POLL);
        }
    }

    #[test]
    fn actual_early_exit_cannot_manufacture_ready() {
        let directory = Directory::new();
        let mut process = child("early_error", &directory);
        assert!(process
            .wait_ready_file(
                &directory.0.join("ready"),
                Instant::now() + Duration::from_secs(2)
            )
            .is_err());
        let outcome = process.finish(Instant::now() + Duration::from_secs(1));
        assert!(outcome.reaped && !outcome.success());
        assert_eq!(outcome.status.unwrap().code(), Some(7));
        assert!(!directory.0.join("ready").exists());
    }

    #[test]
    fn actual_foreign_spectator_roundtrips_after_exact_owner_kill() {
        fn roundtrip(directory: &Directory, value: &[u8]) {
            std::fs::write(directory.0.join("request"), value).unwrap();
            let deadline = Instant::now() + Duration::from_secs(1);
            loop {
                if std::fs::read(directory.0.join("reply")).ok().as_deref() == Some(value) {
                    return;
                }
                assert!(Instant::now() < deadline, "spectator reply deadline");
                thread::sleep(POLL);
            }
        }
        let spectator_directory = Directory::new();
        let mut spectator = child("spectator", &spectator_directory);
        ready(&mut spectator, &spectator_directory);
        roundtrip(&spectator_directory, b"before");
        let directory = Directory::new();
        let mut process = child("hang", &directory);
        ready(&mut process, &directory);
        let outcome = process.finish(Instant::now() + Duration::from_millis(40));
        assert!(outcome.killed && outcome.reaped && !outcome.success());
        assert!(spectator.child.try_wait().unwrap().is_none());
        roundtrip(&spectator_directory, b"after");
        let stopped = spectator.finish(Instant::now() + Duration::from_millis(40));
        assert!(stopped.killed && stopped.reaped);
    }
}
