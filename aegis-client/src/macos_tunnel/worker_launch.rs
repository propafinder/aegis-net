//! Owned non-root launch and private inherited control capabilities. No live
//! macOS policy uses this unit yet. An inherited socketpair
//! proves possession of this launch capability, not fresh peer UID credentials.
use super::{
    worker_accounts,
    worker_ipc::{CancelHandle, Limits, PacketPort, Role},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    time::{Duration, Instant},
};

const CONTROL_FD: RawFd = 0;
const MAX_CONTROL: usize = 8192;
// The admitted session lasts at most 300s capture + 30s startup. A parent
// refreshing once per second needs at most 331 tags including the first grant;
// retain finite headroom, without evicting old tags and permitting replays.
const MAX_RUNTIME_CHALLENGES: usize = 512;
const MAX_PATH: usize = 4096;
const MAX_FILE: u64 = 128 * 1024 * 1024;
const MAX_DESCRIPTOR: RawFd = 1_048_576;
const MAX_RETAINED_DESCRIPTORS: usize = 8192;

fn denied() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "worker launch admission rejected",
    )
}
fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "owned worker control rejected")
}
fn budget(duration: Duration) -> io::Result<Instant> {
    if duration.is_zero() || duration > Duration::from_secs(5) {
        return Err(denied());
    }
    Ok(Instant::now() + duration)
}

fn public_directory_permissions(mode: u32) -> bool {
    mode & 0o022 == 0 && mode & 0o001 != 0
}

fn public_file_permissions(mode: u32, executable: bool) -> bool {
    mode & 0o022 == 0 && mode & 0o6000 == 0 && mode & if executable { 0o001 } else { 0o004 } != 0
}

fn clean_path(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(denied());
    }
    for parent in path.parent().ok_or_else(denied)?.ancestors() {
        let m = fs::symlink_metadata(parent)?;
        if !m.is_dir() || m.uid() != 0 || !public_directory_permissions(m.mode()) {
            return Err(denied());
        }
    }
    Ok(())
}

fn open_trusted(path: &Path, executable: bool, expected: &[u8; 32]) -> io::Result<File> {
    clean_path(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let m = file.metadata()?;
    if !m.is_file()
        || m.uid() != 0
        || m.nlink() != 1
        || m.len() == 0
        || m.len() > if executable { MAX_FILE } else { 1024 * 1024 }
        || !public_file_permissions(m.mode(), executable)
    {
        return Err(denied());
    }
    let mut hash = Sha256::new();
    let mut read = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let bytes = file.read(&mut buffer)?;
        if bytes == 0 {
            break;
        }
        read += bytes as u64;
        if read > m.len() {
            return Err(denied());
        }
        hash.update(&buffer[..bytes]);
    }
    if read != m.len() || hash.finalize().as_slice() != expected {
        return Err(denied());
    }
    use std::io::Seek;
    file.rewind()?;
    let path_m = fs::symlink_metadata(path)?;
    if path_m.dev() != m.dev()
        || path_m.ino() != m.ino()
        || path_m.mtime() != m.mtime()
        || path_m.len() != m.len()
    {
        return Err(denied());
    }
    Ok(file)
}

pub(super) fn open_public_profile(path: &Path, expected: &[u8; 32]) -> io::Result<File> {
    open_trusted(path, false, expected)
}

/// A production admission can only originate from actual native account
/// discovery plus root-owned reviewed SHA-256 executable/profile and custody.
pub(crate) struct VerifiedLaunch {
    account: worker_accounts::VerifiedAccount,
    executable: PathBuf,
    executable_file: File,
    executable_sha256: [u8; 32],
    profile: File,
    profile_sha256: [u8; 32],
    bootstrap: Bootstrap,
}
impl VerifiedLaunch {
    pub(crate) fn prepare(
        name: &str,
        executable: &Path,
        executable_sha256: [u8; 32],
        identity: &Path,
        profile: &Path,
        profile_sha256: [u8; 32],
    ) -> io::Result<Self> {
        if unsafe { libc::geteuid() } != 0 || unsafe { libc::getuid() } != 0 {
            return Err(denied());
        }
        let account = worker_accounts::discover(name)?;
        account.admission.validate_custody(identity, profile)?;
        let executable_file = open_trusted(executable, true, &executable_sha256)?;
        let profile_file = open_trusted(profile, false, &profile_sha256)?;
        let (uid, gid) = account.admission.ids();
        let bootstrap = Bootstrap::new(name, uid, gid, identity, profile, profile_sha256)?;
        Ok(Self {
            account,
            executable: executable.to_owned(),
            executable_file,
            executable_sha256,
            profile: profile_file,
            profile_sha256,
            bootstrap,
        })
    }
    pub(crate) fn spawn(self, timeout: Duration) -> io::Result<OwnedNetworkWorker> {
        // Refresh native sharing and path/custody admission immediately before
        // spawn. This is not an OS lock against a trusted administrator change.
        let current = worker_accounts::discover(&self.account.name)?;
        if current.admission.ids() != self.account.admission.ids() {
            return Err(denied());
        }
        current.admission.validate_custody(
            Path::new(&self.bootstrap.identity),
            Path::new(&self.bootstrap.profile_path),
        )?;
        let m = self.executable_file.metadata()?;
        // Refresh root ownership, permissions, ancestry and digest as well as
        // descriptor identity. chmod/chown do not necessarily change mtime.
        let checked_executable = open_trusted(&self.executable, true, &self.executable_sha256)?;
        let path_m = checked_executable.metadata()?;
        if (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec())
            != (
                path_m.dev(),
                path_m.ino(),
                path_m.len(),
                path_m.mtime(),
                path_m.mtime_nsec(),
            )
        {
            return Err(denied());
        }
        // The worker reopens the public profile after dropping privileges.
        // Reject root-only read/traversal shapes again before spawning; do not
        // loosen the separate private identity store to make this usable.
        let checked_profile = open_trusted(
            Path::new(&self.bootstrap.profile_path),
            false,
            &self.profile_sha256,
        )?;
        let (held, checked) = (self.profile.metadata()?, checked_profile.metadata()?);
        if (
            held.dev(),
            held.ino(),
            held.len(),
            held.mtime(),
            held.mtime_nsec(),
        ) != (
            checked.dev(),
            checked.ino(),
            checked.len(),
            checked.mtime(),
            checked.mtime_nsec(),
        ) {
            return Err(denied());
        }
        let mut command = Command::new(&self.executable);
        command.arg("--macos-network-worker-internal");
        command.uid(self.bootstrap.uid).gid(self.bootstrap.gid);
        spawn_capabilities(command, self.profile, self.bootstrap, timeout, true)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bootstrap {
    account: String,
    uid: u32,
    gid: u32,
    nonce: String,
    identity: String,
    profile_path: String,
    profile_sha256: String,
    packet_fd: RawFd,
    profile_fd: RawFd,
}
impl Bootstrap {
    fn new(
        account: &str,
        uid: u32,
        gid: u32,
        identity: &Path,
        profile: &Path,
        profile_sha256: [u8; 32],
    ) -> io::Result<Self> {
        let text = |p: &Path| -> io::Result<String> {
            let text = p.to_str().ok_or_else(denied)?;
            if text.len() > MAX_PATH
                || !p.is_absolute()
                || p.components()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                return Err(denied());
            }
            Ok(text.to_owned())
        };
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);
        Ok(Self {
            account: account.into(),
            uid,
            gid,
            nonce: hex::encode(nonce),
            identity: text(identity)?,
            profile_path: text(profile)?,
            profile_sha256: hex::encode(profile_sha256),
            packet_fd: 0,
            profile_fd: 0,
        })
    }
    fn validate(&self) -> io::Result<()> {
        if self.nonce.len() != 32
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.profile_sha256.len() != 64
            || !self
                .profile_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.account.len() > 64
            || !self.account.starts_with("_aegis_")
            || self.identity.len() > MAX_PATH
            || self.profile_path.len() > MAX_PATH
            || !(16..1_048_576).contains(&self.packet_fd)
            || !(16..1_048_576).contains(&self.profile_fd)
            || self.packet_fd == self.profile_fd
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "state", deny_unknown_fields)]
enum Report {
    IdentityPrepared {
        pid: u32,
        nonce: String,
        challenge: String,
    },
    Started {
        pid: u32,
        uid: u32,
        gid: u32,
        nonce: String,
    },
    EngineConstructed {
        pid: u32,
        nonce: String,
    },
    PolicyConfirmed {
        pid: u32,
        nonce: String,
        challenge: String,
        certificate_sha256: String,
        remaining_ms: u64,
        valid_until_ns: u64,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RelayPermission {
    challenge: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CaptureChallenge {
    challenge: String,
    deadline_ns: u64,
}

fn canonical_nonce(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn poll_pause(deadline: Instant) -> io::Result<()> {
    if Instant::now() >= deadline {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "owned worker deadline exceeded",
        ));
    }
    std::thread::sleep(Duration::from_millis(2));
    Ok(())
}
fn transfer(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
    write: bool,
) -> io::Result<()> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned worker deadline exceeded",
            ));
        }
        let result = if write {
            stream.write(bytes)
        } else {
            stream.read(bytes)
        };
        match result {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "owned worker control closed",
                ))
            }
            Ok(n) => bytes = &mut bytes[n..],
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => poll_pause(deadline)?,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn send<T: Serialize>(stream: &mut UnixStream, value: &T, deadline: Instant) -> io::Result<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.is_empty() || bytes.len() > MAX_CONTROL {
        return Err(invalid());
    }
    let mut header = [b'A', b'W', 2, 1, 0, 0, 0, 0];
    header[4..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
    transfer(stream, &mut header, deadline, true)?;
    transfer(stream, &mut bytes, deadline, true)
}
fn receive<T: serde::de::DeserializeOwned>(
    stream: &mut UnixStream,
    deadline: Instant,
) -> io::Result<T> {
    let mut header = [0; 8];
    transfer(stream, &mut header, deadline, false)?;
    let length = u32::from_be_bytes(header[4..].try_into().unwrap()) as usize;
    if header[..4] != [b'A', b'W', 2, 1] || !(1..=MAX_CONTROL).contains(&length) {
        return Err(invalid());
    }
    let mut bytes = vec![0; length];
    transfer(stream, &mut bytes, deadline, false)?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    let duplicated = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 16) };
    if duplicated < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(duplicated) })
}
fn groups_exclusive(gid: u32) -> io::Result<()> {
    let mut groups = [0u32; 128];
    let count = unsafe { libc::getgroups(groups.len() as libc::c_int, groups.as_mut_ptr()) };
    if count < 0 || groups[..count as usize].iter().any(|g| *g != gid) {
        return Err(denied());
    }
    Ok(())
}

fn descriptor_bound_from_inventory(
    kernel_ceiling: RawFd,
    allocated_capacity: usize,
    retained: &[libc::proc_fdinfo],
) -> io::Result<RawFd> {
    if !(6..=MAX_DESCRIPTOR).contains(&kernel_ceiling)
        || !(1..=MAX_DESCRIPTOR as usize).contains(&allocated_capacity)
        || retained.is_empty()
        || retained.len() >= MAX_RETAINED_DESCRIPTORS
    {
        return Err(denied());
    }
    let mut bound = kernel_ceiling.max(allocated_capacity as RawFd);
    for entry in retained {
        if !(0..MAX_DESCRIPTOR).contains(&entry.proc_fd) {
            return Err(denied());
        }
        bound = bound.max(entry.proc_fd + 1);
    }
    Ok(bound)
}

fn descriptor_scan_bound() -> io::Result<RawFd> {
    // getdtablesize and both RLIMIT values can shrink below already-open FDs.
    // Read the kernel allocation ceiling first, then the allocated native table
    // bound and retained descriptor inventory. Normal concurrent opens stay
    // below that kernel ceiling; the allocated bound includes older reserved
    // slots, and retained higher FDs survive earlier ceiling reductions.
    // A trusted administrator changing kernel limits during spawn is outside
    // this snapshot contract, just like a root executable/account rewrite.
    let mut kernel_ceiling: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&kernel_ceiling);
    if unsafe {
        libc::sysctlbyname(
            c"kern.maxfilesperproc".as_ptr(),
            (&mut kernel_ceiling as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    if size != std::mem::size_of_val(&kernel_ceiling) {
        return Err(denied());
    }
    if !(6..=MAX_DESCRIPTOR).contains(&kernel_ceiling) {
        return Err(denied());
    }
    // Native XNU's null-buffer query includes the allocated descriptor table
    // size plus margin, not just the lowered soft limit or settled open count.
    // Keep the full returned count as an upper bound; never subtract margin.
    let required = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            std::ptr::null_mut(),
            0,
        )
    };
    let item_size = std::mem::size_of::<libc::proc_fdinfo>();
    if required <= 0
        || !(required as usize).is_multiple_of(item_size)
        || required as usize / item_size > MAX_DESCRIPTOR as usize
    {
        return Err(denied());
    }
    let allocated_capacity = required as usize / item_size;
    let mut retained = vec![
        libc::proc_fdinfo {
            proc_fd: 0,
            proc_fdtype: 0,
        };
        MAX_RETAINED_DESCRIPTORS
    ];
    let bytes = std::mem::size_of_val(retained.as_slice());
    let returned = unsafe {
        libc::proc_pidinfo(
            libc::getpid(),
            libc::PROC_PIDLISTFDS,
            0,
            retained.as_mut_ptr().cast(),
            bytes as libc::c_int,
        )
    };
    // A full response might be truncated, so refuse rather than assume every
    // retained capability was enumerated. No soft/hard-limit fallback is safe.
    if returned <= 0 || returned as usize >= bytes || !(returned as usize).is_multiple_of(item_size)
    {
        return Err(denied());
    }
    descriptor_bound_from_inventory(
        kernel_ceiling,
        allocated_capacity,
        &retained[..returned as usize / std::mem::size_of::<libc::proc_fdinfo>()],
    )
}

fn spawn_capabilities(
    mut command: Command,
    profile: File,
    mut bootstrap: Bootstrap,
    timeout: Duration,
    privilege_drop: bool,
) -> io::Result<OwnedNetworkWorker> {
    let deadline = budget(timeout)?;
    let (parent_packet, child_packet) = UnixStream::pair()?;
    let (parent_control, child_control) = UnixStream::pair()?;
    parent_control.set_nonblocking(true)?;
    child_control.set_nonblocking(true)?;
    let packet = duplicate(child_packet.as_raw_fd())?;
    let profile_fd = duplicate(profile.as_raw_fd())?;
    // Keep these source descriptors held until after spawn. They cannot alias
    // std::Command's private exec-error pipe. Convey their numbers only over
    // the private stdio control capability, never argv/environment.
    let inherited = [packet.as_raw_fd(), profile_fd.as_raw_fd()];
    bootstrap.packet_fd = inherited[0];
    bootstrap.profile_fd = inherited[1];
    bootstrap.validate()?;
    let max_fd = descriptor_scan_bound()?;
    let (uid, gid) = (bootstrap.uid, bootstrap.gid);
    let stdin: OwnedFd = child_control.try_clone()?.into();
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(stdin))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Rust's uid() clears supplementary groups before setuid unless explicit
    // groups were specified. The closure only performs async-signal-safe syscalls
    // and verifies the result; it never allocates, locks or reads env/files.
    unsafe {
        command.pre_exec(move || {
            for fd in 3..max_fd {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                let updated = if inherited.contains(&fd) {
                    flags & !libc::FD_CLOEXEC
                } else {
                    flags | libc::FD_CLOEXEC
                };
                if flags < 0 && *libc::__error() != libc::EBADF
                    || flags >= 0 && libc::fcntl(fd, libc::F_SETFD, updated) < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
            if privilege_drop {
                if libc::getuid() != uid
                    || libc::geteuid() != uid
                    || libc::getgid() != gid
                    || libc::getegid() != gid
                    || uid == 0
                {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
                // Bounded stack storage; no caller-provided supplementary identity.
                let mut groups = [0u32; 128];
                let n = libc::getgroups(128, groups.as_mut_ptr());
                if n < 0 || groups[..n as usize].iter().any(|g| *g != gid) {
                    return Err(io::Error::from_raw_os_error(libc::EPERM));
                }
            }
            Ok(())
        });
    }
    let (port, cancel) = PacketPort::new(parent_packet, Role::Parent, Limits::default())?;
    let nonce = bootstrap.nonce.clone();
    let child = command.spawn()?;
    let mut owner = OwnedNetworkWorker {
        child: Some(child),
        port,
        cancel,
        control: parent_control,
        uid,
        gid,
        nonce,
        engine: None,
        identity_event: None,
        relay_permitted: false,
        exit: None,
    };
    drop(command);
    drop(child_packet);
    drop(child_control);
    drop(packet);
    drop(profile_fd);
    drop(profile);
    let result = (|| {
        send(&mut owner.control, &bootstrap, deadline)?;
        match receive::<Report>(&mut owner.control, deadline)? {
            Report::Started {
                pid,
                uid,
                gid,
                nonce,
            } if pid == owner.id()
                && uid == owner.uid
                && gid == owner.gid
                && nonce == owner.nonce =>
            {
                Ok(())
            }
            _ => Err(invalid()),
        }
    })();
    if let Err(error) = result {
        owner.cancel(Duration::from_secs(2))?;
        return Err(error);
    }
    Ok(owner)
}

pub(crate) struct EngineConstructed {
    pid: u32,
}
/// This token can only originate from the existing authenticated targetless
/// relay operation; a control report or local engine event cannot create it.
pub(crate) struct AuthenticatedPolicyAck {
    valid_until: tokio::time::Instant,
    certificate_sha256: String,
}
impl AuthenticatedPolicyAck {
    pub(crate) async fn confirm(
        relay: &aegis_core::RelaySettings,
        expected: &aegis_client::online_expectation::OnlineExpectation,
    ) -> anyhow::Result<Self> {
        let valid_until = crate::relay::policy_ack(relay, expected).await?;
        anyhow::ensure!(
            valid_until > tokio::time::Instant::now(),
            "authenticated policy ACK expired"
        );
        Ok(Self {
            valid_until,
            certificate_sha256: expected.certificate_sha256.clone(),
        })
    }
}
pub(crate) struct CaptureAdmission {
    pid: u32,
    nonce: String,
    valid_until_ns: u64,
}
impl CaptureAdmission {
    pub(crate) fn is_unexpired(&self) -> io::Result<bool> {
        Ok(monotonic_ns()? < self.valid_until_ns)
    }
    pub(crate) fn is_current_for(&self, worker: &mut OwnedNetworkWorker) -> io::Result<bool> {
        Ok(self.is_unexpired()?
            && self.pid == worker.id()
            && self.nonce == worker.nonce
            && worker
                .child
                .as_mut()
                .ok_or_else(denied)?
                .try_wait()?
                .is_none())
    }
}

/// Stopped-ingress identity preparation, not a relay/capture authorization.
pub(crate) struct PreparedIdentityEvent {
    pid: u32,
    nonce: String,
    challenge: String,
}
impl PreparedIdentityEvent {
    pub(crate) fn is_current_for(&self, worker: &mut OwnedNetworkWorker) -> io::Result<bool> {
        Ok(self.pid == worker.id()
            && self.nonce == worker.nonce
            && worker.identity_event.as_ref() == Some(&self.challenge)
            && !worker.relay_permitted
            && worker
                .child
                .as_mut()
                .ok_or_else(denied)?
                .try_wait()?
                .is_none())
    }
}

/// Constructed only by successful wait/reaping of this exact owned Child.
/// Drop/background fallback reaping cannot produce a policy rollback token.
pub(crate) struct ConfirmedWorkerExit {
    pid: u32,
    nonce: String,
    uid: u32,
    gid: u32,
    status: ExitStatus,
}
impl ConfirmedWorkerExit {
    pub(crate) fn matches_binding(&self, pid: u32, nonce: &str) -> bool {
        self.pid == pid && self.nonce == nonce
    }
    pub(super) fn matches_account(&self, account: &worker_accounts::VerifiedAccount) -> bool {
        account.admission.ids() == (self.uid, self.gid)
    }
    pub(crate) fn status(&self) -> &ExitStatus {
        &self.status
    }
}

pub(crate) struct OwnedNetworkWorker {
    child: Option<Child>,
    pub(crate) port: PacketPort,
    cancel: CancelHandle,
    control: UnixStream,
    uid: u32,
    gid: u32,
    nonce: String,
    engine: Option<EngineConstructed>,
    identity_event: Option<String>,
    relay_permitted: bool,
    exit: Option<ConfirmedWorkerExit>,
}
impl OwnedNetworkWorker {
    pub(crate) fn generation_nonce(&self) -> &str {
        &self.nonce
    }
    pub(super) fn matches_account(&self, account: &worker_accounts::VerifiedAccount) -> bool {
        self.child.is_some() && account.admission.ids() == (self.uid, self.gid)
    }
    pub(crate) fn id(&self) -> u32 {
        self.child.as_ref().map(Child::id).unwrap_or(0)
    }
    pub(crate) fn await_identity_prepared(
        &mut self,
        timeout: Duration,
    ) -> io::Result<PreparedIdentityEvent> {
        if timeout.is_zero() || timeout > Duration::from_secs(30) || self.identity_event.is_some() {
            return Err(denied());
        }
        let result = (|| match receive::<Report>(&mut self.control, Instant::now() + timeout)? {
            Report::IdentityPrepared {
                pid,
                nonce,
                challenge,
            } if pid == self.id()
                && nonce == self.nonce
                && canonical_nonce(&challenge)
                && self
                    .child
                    .as_mut()
                    .ok_or_else(denied)?
                    .try_wait()?
                    .is_none() =>
            {
                self.identity_event = Some(challenge.clone());
                Ok(PreparedIdentityEvent {
                    pid,
                    nonce,
                    challenge,
                })
            }
            _ => Err(invalid()),
        })();
        if result.is_err() {
            self.cancel(Duration::from_secs(2))?;
        }
        result
    }
    /// Caller installs its exact relay-only policy before releasing the child.
    /// This permission enables a real ACK attempt; it is not an ACK token.
    pub(crate) fn permit_relay(
        &mut self,
        prepared: &PreparedIdentityEvent,
        timeout: Duration,
    ) -> io::Result<()> {
        let deadline = budget(timeout)?;
        if !prepared.is_current_for(self)? {
            return Err(denied());
        }
        let result = send(
            &mut self.control,
            &RelayPermission {
                challenge: prepared.challenge.clone(),
            },
            deadline,
        );
        if result.is_err() {
            self.cancel(Duration::from_secs(2))?;
        }
        result?;
        self.relay_permitted = true;
        Ok(())
    }
    /// Started/engine construction alone cannot admit capture. A missing ACK,
    /// out-of-order/stale/foreign report fails and terminates only this child.
    pub(crate) fn await_capture_admission(
        &mut self,
        timeout: Duration,
    ) -> io::Result<CaptureAdmission> {
        let deadline = budget(timeout)?;
        if !self.relay_permitted {
            return Err(denied());
        }
        let mut challenge = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut challenge);
        let challenge = hex::encode(challenge);
        let request_deadline_ns = monotonic_deadline(timeout)?;
        // An existing engine accepts only a fresh challenge/report, never a
        // second construction event. Each short grant requires a new live ACK.
        if self.engine.is_some() {
            if let Err(error) = send(
                &mut self.control,
                &CaptureChallenge {
                    challenge: challenge.clone(),
                    deadline_ns: request_deadline_ns,
                },
                deadline,
            ) {
                self.cancel(Duration::from_secs(2))?;
                return Err(error);
            }
        }
        let result = (|| loop {
            if self
                .child
                .as_mut()
                .ok_or_else(denied)?
                .try_wait()?
                .is_some()
            {
                return Err(invalid());
            }
            match receive::<Report>(&mut self.control, deadline)? {
                Report::EngineConstructed { pid, nonce }
                    if pid == self.id() && nonce == self.nonce && self.engine.is_none() =>
                {
                    self.engine = Some(EngineConstructed { pid });
                    // Carry a shared kernel-clock cutoff. The real ACK and
                    // both process gates intersect this exact deadline; queued
                    // control transit cannot extend the parent grant.
                    send(
                        &mut self.control,
                        &CaptureChallenge {
                            challenge: challenge.clone(),
                            deadline_ns: request_deadline_ns,
                        },
                        deadline,
                    )?;
                }
                Report::PolicyConfirmed {
                    pid,
                    nonce,
                    challenge: reply,
                    certificate_sha256,
                    remaining_ms,
                    valid_until_ns,
                } if pid == self.id()
                    && nonce == self.nonce
                    && reply == challenge
                    && self.engine.as_ref().is_some_and(|e| e.pid == pid)
                    && (1..=5000).contains(&remaining_ms)
                    && certificate_sha256.len() == 64
                    && certificate_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
                {
                    if valid_until_ns > request_deadline_ns || monotonic_ns()? >= valid_until_ns {
                        return Err(invalid());
                    }
                    return Ok(CaptureAdmission {
                        pid,
                        nonce: self.nonce.clone(),
                        valid_until_ns,
                    });
                }
                _ => return Err(invalid()),
            }
        })();
        if result.is_err() {
            self.cancel(Duration::from_secs(2))?;
        }
        result
    }
    pub(crate) fn cancel_owned(&mut self, timeout: Duration) -> io::Result<ConfirmedWorkerExit> {
        if let Some(exit) = self.exit.take() {
            return Ok(exit);
        }
        self.cancel(timeout)?;
        self.exit.take().ok_or_else(denied)
    }
    fn retain_exit(&mut self, pid: u32, status: ExitStatus) -> ExitStatus {
        self.child = None;
        self.exit = Some(ConfirmedWorkerExit {
            pid,
            nonce: self.nonce.clone(),
            uid: self.uid,
            gid: self.gid,
            status,
        });
        status
    }
    pub(crate) fn cancel(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let deadline = budget(timeout)?;
        self.cancel.cancel();
        let _ = self.control.shutdown(Shutdown::Both);
        let pid = self.id();
        let child = self.child.as_mut().ok_or_else(denied)?;
        if let Some(status) = child.try_wait()? {
            return Ok(self.retain_exit(pid, status));
        }
        if let Err(error) = child.kill() {
            if child.try_wait()?.is_none() {
                return Err(error);
            }
        }
        loop {
            if let Some(status) = child.try_wait()? {
                return Ok(self.retain_exit(pid, status));
            }
            poll_pause(deadline)?;
        }
    }
}
impl Drop for OwnedNetworkWorker {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = self.control.shutdown(Shutdown::Both);
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            // Drop cannot attest reaping or authorize policy rollback. The
            // fallback reaper owns only this exact Child, never a PID search.
            let _ = std::thread::Builder::new()
                .name("owned-worker-reaper".into())
                .spawn(move || {
                    let _ = child.wait();
                });
        }
    }
}

pub(crate) struct WorkerBootstrap {
    pub(crate) port: PacketPort,
    pub(crate) identity: PathBuf,
    pub(crate) profile: File,
    control: UnixStream,
    nonce: String,
    cancel: CancelHandle,
}
impl WorkerBootstrap {
    pub(super) fn into_runtime(self) -> io::Result<RuntimeParts> {
        Ok(RuntimeParts {
            port: self.port,
            cancel: self.cancel,
            identity: self.identity,
            profile: self.profile,
            control: RuntimeControl {
                socket: tokio::net::UnixStream::from_std(self.control)?,
                nonce: self.nonce,
                engine: false,
                prepared: false,
                relay_permitted: false,
                challenges: std::collections::BTreeSet::new(),
                header: [0; 8],
                header_read: 0,
                payload: Vec::new(),
                payload_read: 0,
            },
        })
    }
    pub(crate) fn engine_constructed(&mut self) -> io::Result<EngineConstructed> {
        let pid = std::process::id();
        send(
            &mut self.control,
            &Report::EngineConstructed {
                pid,
                nonce: self.nonce.clone(),
            },
            budget(Duration::from_secs(1))?,
        )?;
        Ok(EngineConstructed { pid })
    }
    pub(crate) fn report_authenticated_policy(
        &mut self,
        engine: &EngineConstructed,
        ack: &AuthenticatedPolicyAck,
    ) -> io::Result<()> {
        if engine.pid != std::process::id() {
            return Err(denied());
        }
        let deadline = budget(Duration::from_secs(1))?;
        let CaptureChallenge {
            challenge,
            deadline_ns,
        } = receive::<CaptureChallenge>(&mut self.control, deadline)?;
        if challenge.len() != 32
            || !challenge
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(invalid());
        }
        let now_ns = monotonic_ns()?;
        if deadline_ns <= now_ns || deadline_ns - now_ns > 5_000_000_000 {
            return Err(denied());
        }
        let remaining = ack
            .valid_until
            .saturating_duration_since(tokio::time::Instant::now())
            .min(Duration::from_nanos(deadline_ns - now_ns))
            .min(Duration::from_secs(5))
            .as_millis() as u64;
        if remaining == 0 {
            return Err(denied());
        }
        send(
            &mut self.control,
            &Report::PolicyConfirmed {
                pid: engine.pid,
                nonce: self.nonce.clone(),
                challenge,
                certificate_sha256: ack.certificate_sha256.clone(),
                remaining_ms: remaining,
                valid_until_ns: now_ns + remaining * 1_000_000,
            },
            deadline,
        )
    }
}

/// Sole internal entry must call this once before constructing Tokio or network
/// sockets. Stdin is the private Unix control capability; its bootstrap names
/// the already-held packet/profile descriptors, without argv/environment values.
/// No environment/argument value can supply a credential or readiness proof.
/// # Safety
/// The caller must own the inherited control and named descriptors exclusively and never
/// call this function after another owner has consumed or closed them.
pub(crate) unsafe fn accept_inherited(timeout: Duration) -> io::Result<WorkerBootstrap> {
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    if uid == 0 || unsafe { libc::getuid() } != uid || unsafe { libc::getgid() } != gid {
        return Err(denied());
    }
    groups_exclusive(gid)?;
    let mut control = unsafe { UnixStream::from_raw_fd(CONTROL_FD) };
    control.set_nonblocking(true)?;
    let deadline = budget(timeout)?;
    let bootstrap: Bootstrap = receive(&mut control, deadline)?;
    bootstrap.validate()?;
    for fd in [bootstrap.packet_fd, CONTROL_FD] {
        let mut kind = 0;
        let mut size = std::mem::size_of_val(&kind) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut size,
            )
        } < 0
            || kind != libc::SOCK_STREAM
        {
            return Err(denied());
        }
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_un).cast(),
                &mut length,
            )
        } < 0
            || address.sun_family as libc::c_int != libc::AF_UNIX
        {
            return Err(denied());
        }
        length = std::mem::size_of_val(&address) as libc::socklen_t;
        if unsafe {
            libc::getpeername(
                fd,
                (&mut address as *mut libc::sockaddr_un).cast(),
                &mut length,
            )
        } < 0
            || address.sun_family as libc::c_int != libc::AF_UNIX
        {
            return Err(denied());
        }
    }
    let packet = unsafe { UnixStream::from_raw_fd(bootstrap.packet_fd) };
    let profile = unsafe { File::from_raw_fd(bootstrap.profile_fd) };
    if unsafe { libc::fcntl(profile.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE
        != libc::O_RDONLY
    {
        return Err(denied());
    }
    let account = worker_accounts::discover(&bootstrap.account)?;
    if (uid, gid) != (bootstrap.uid, bootstrap.gid) || account.admission.ids() != (uid, gid) {
        return Err(denied());
    }
    account.admission.validate_custody(
        Path::new(&bootstrap.identity),
        Path::new(&bootstrap.profile_path),
    )?;
    let digest: [u8; 32] = hex::decode(&bootstrap.profile_sha256)
        .map_err(|_| invalid())?
        .try_into()
        .map_err(|_| invalid())?;
    let checked = open_trusted(Path::new(&bootstrap.profile_path), false, &digest)?;
    let (m, c) = (profile.metadata()?, checked.metadata()?);
    if (m.dev(), m.ino(), m.len(), m.mtime(), m.mtime_nsec())
        != (c.dev(), c.ino(), c.len(), c.mtime(), c.mtime_nsec())
    {
        return Err(denied());
    }
    let (port, cancel) = PacketPort::new(packet, Role::Worker, Limits::default())?;
    send(
        &mut control,
        &Report::Started {
            pid: std::process::id(),
            uid,
            gid,
            nonce: bootstrap.nonce.clone(),
        },
        deadline,
    )?;
    Ok(WorkerBootstrap {
        port,
        identity: PathBuf::from(bootstrap.identity),
        profile,
        control,
        nonce: bootstrap.nonce,
        cancel,
    })
}

pub(crate) struct RuntimeParts {
    pub port: PacketPort,
    pub cancel: CancelHandle,
    pub identity: PathBuf,
    pub profile: File,
    pub control: RuntimeControl,
}

/// Exclusive, bounded control stream. A cancelled partial operation ends the
/// runtime; it is never resumed as a different frame. Reports cannot mint ACKs.
pub(super) struct RuntimeChallenge {
    challenge: String,
    deadline_ns: u64,
}

/// macOS kernel-wide continuous monotonic nanoseconds. Both owned processes
/// check this same clock; no wall-clock or process-relative epoch is serialized.
pub(crate) fn monotonic_ns() -> io::Result<u64> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC_RAW, &mut value) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if value.tv_sec < 0 || !(0..1_000_000_000).contains(&value.tv_nsec) {
        return Err(invalid());
    }
    (value.tv_sec as u64)
        .checked_mul(1_000_000_000)
        .and_then(|v| v.checked_add(value.tv_nsec as u64))
        .ok_or_else(invalid)
}
pub(crate) fn monotonic_deadline(duration: Duration) -> io::Result<u64> {
    if duration.is_zero() || duration > Duration::from_secs(5) {
        return Err(denied());
    }
    monotonic_ns()?
        .checked_add(duration.as_nanos() as u64)
        .ok_or_else(invalid)
}

pub(crate) struct RuntimeControl {
    socket: tokio::net::UnixStream,
    nonce: String,
    engine: bool,
    prepared: bool,
    relay_permitted: bool,
    challenges: std::collections::BTreeSet<String>,
    header: [u8; 8],
    header_read: usize,
    payload: Vec<u8>,
    payload_read: usize,
}
impl RuntimeControl {
    async fn send<T: Serialize>(&mut self, value: &T) -> io::Result<()> {
        use tokio::io::AsyncWriteExt;
        let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
        if !(1..=MAX_CONTROL).contains(&bytes.len()) {
            return Err(invalid());
        }
        let mut header = [b'A', b'W', 2, 1, 0, 0, 0, 0];
        header[4..].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        tokio::time::timeout(Duration::from_secs(1), async {
            self.socket.write_all(&header).await?;
            self.socket.write_all(&bytes).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "worker control deadline"))?
    }
    pub(super) async fn identity_prepared(&mut self) -> io::Result<String> {
        if self.prepared || self.engine {
            return Err(invalid());
        }
        let mut challenge = [0; 16];
        rand::thread_rng().fill_bytes(&mut challenge);
        let challenge = hex::encode(challenge);
        self.send(&Report::IdentityPrepared {
            pid: std::process::id(),
            nonce: self.nonce.clone(),
            challenge: challenge.clone(),
        })
        .await?;
        self.prepared = true;
        Ok(challenge)
    }
    pub(super) async fn relay_permission(&mut self, challenge: &str) -> io::Result<()> {
        let permission: RelayPermission = self.receive().await?;
        if !self.prepared || self.relay_permitted || permission.challenge != challenge {
            return Err(invalid());
        }
        self.relay_permitted = true;
        Ok(())
    }
    /// Startup/ACK cancellation waits on this future only to detect EOF or an
    /// unexpected input. Every completion terminates the runtime, so cancelled
    /// partial frames are never retried with a new parser.
    pub(super) async fn unexpected(&mut self) -> io::Result<()> {
        let _: serde_json::Value = self.receive().await?;
        Err(invalid())
    }
    pub(super) fn require_idle(&self) -> io::Result<()> {
        if self.header_read == 0 && self.payload.is_empty() {
            Ok(())
        } else {
            Err(invalid())
        }
    }
    async fn receive<T: serde::de::DeserializeOwned>(&mut self) -> io::Result<T> {
        use tokio::io::AsyncReadExt;
        // read() is cancellation safe. Progress belongs to this control owner,
        // not the disposable receive future used in select! startup guards.
        while self.header_read < self.header.len() {
            let n = self
                .socket
                .read(&mut self.header[self.header_read..])
                .await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.header_read += n;
        }
        let length = u32::from_be_bytes(self.header[4..].try_into().unwrap()) as usize;
        if self.header[..4] != [b'A', b'W', 2, 1] || !(1..=MAX_CONTROL).contains(&length) {
            return Err(invalid());
        }
        if self.payload.is_empty() {
            self.payload.resize(length, 0);
        }
        while self.payload_read < length {
            let n = self
                .socket
                .read(&mut self.payload[self.payload_read..])
                .await?;
            if n == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            self.payload_read += n;
        }
        let result = serde_json::from_slice(&self.payload).map_err(|_| invalid());
        self.header_read = 0;
        self.payload.clear();
        self.payload_read = 0;
        result
    }
    pub(super) async fn engine_constructed(&mut self) -> io::Result<()> {
        if self.engine || !self.prepared || !self.relay_permitted {
            return Err(invalid());
        }
        self.send(&Report::EngineConstructed {
            pid: std::process::id(),
            nonce: self.nonce.clone(),
        })
        .await?;
        self.engine = true;
        Ok(())
    }
    pub(super) async fn challenge(&mut self) -> io::Result<RuntimeChallenge> {
        let request: CaptureChallenge = self.receive().await?;
        if !self.engine
            || request.challenge.len() != 32
            || !request
                .challenge
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self.challenges.len() >= MAX_RUNTIME_CHALLENGES
            || !self.challenges.insert(request.challenge.clone())
        {
            return Err(invalid());
        }
        let now = monotonic_ns()?;
        if request.deadline_ns <= now || request.deadline_ns - now > 5_000_000_000 {
            return Err(denied());
        }
        Ok(RuntimeChallenge {
            challenge: request.challenge,
            deadline_ns: request.deadline_ns,
        })
    }
    pub(super) async fn policy_confirmed(
        &mut self,
        challenge: RuntimeChallenge,
        ack: &AuthenticatedPolicyAck,
    ) -> io::Result<u64> {
        if !self.engine || !self.challenges.contains(&challenge.challenge) {
            return Err(invalid());
        }
        let now_ns = monotonic_ns()?;
        if now_ns >= challenge.deadline_ns {
            return Err(denied());
        }
        let remaining = ack
            .valid_until
            .saturating_duration_since(tokio::time::Instant::now())
            .min(Duration::from_secs(5))
            .min(Duration::from_nanos(challenge.deadline_ns - now_ns));
        let remaining_ms = remaining.as_millis() as u64;
        if remaining_ms == 0 {
            return Err(denied());
        }
        let expires = now_ns + remaining_ms * 1_000_000;
        let report = Report::PolicyConfirmed {
            pid: std::process::id(),
            nonce: self.nonce.clone(),
            challenge: challenge.challenge,
            certificate_sha256: ack.certificate_sha256.clone(),
            remaining_ms,
            valid_until_ns: expires,
        };
        tokio::time::timeout(remaining, self.send(&report))
            .await
            .map_err(|_| {
                io::Error::new(io::ErrorKind::TimedOut, "worker policy lease expired")
            })??;
        if monotonic_ns()? >= expires {
            return Err(denied());
        }
        Ok(expires)
    }
}

#[cfg(test)]
pub(crate) fn local_runtime_fixture(
    identity: PathBuf,
    profile: File,
) -> (RuntimeParts, tokio::net::UnixStream, PacketPort) {
    // Current-UID socketpairs exercise runtime/cancellation only. They do not
    // bypass production entry or prove native dedicated-account privilege drop.
    let (packet, parent_packet) = UnixStream::pair().unwrap();
    let (control, parent_control) = UnixStream::pair().unwrap();
    control.set_nonblocking(true).unwrap();
    parent_control.set_nonblocking(true).unwrap();
    let (port, cancel) = PacketPort::new(packet, Role::Worker, Limits::default()).unwrap();
    let (parent, _) = PacketPort::new(parent_packet, Role::Parent, Limits::default()).unwrap();
    (
        RuntimeParts {
            port,
            cancel,
            identity,
            profile,
            control: RuntimeControl {
                socket: tokio::net::UnixStream::from_std(control).unwrap(),
                nonce: "12".repeat(16),
                engine: false,
                prepared: false,
                relay_permitted: false,
                challenges: Default::default(),
                header: [0; 8],
                header_read: 0,
                payload: Vec::new(),
                payload_read: 0,
            },
        },
        tokio::net::UnixStream::from_std(parent_control).unwrap(),
        parent,
    )
}

#[cfg(test)]
#[path = "worker_launch_tests.rs"]
mod tests;
