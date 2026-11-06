//! PRIVATE UNAPPLIED actual root prepare input admission, nested transaction.
//! Source only; author has not executed resolver/native commands. Captured main,
//! passwd and administrative markers remain held and metadata-revalidated after
//! child planning; no selected original bytes are read again after child prepare.
use super::refuse;
use crate::profile_auto_capture::{CaptureLimits, CapturedInput, CapturedTree, InputRole};
use crate::profile_auto_prepare as prepare;
use crate::profile_auto_render::RelayPin;
use crate::profile_auto_transaction_cli::{ExistingChoice, PrepareArgs};
use aegis_core::Settings;
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::{ffi::OsStrExt, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
type Result<T> = std::result::Result<T, String>;
fn err<T>(_: T) -> String {
    refuse()
}
fn fd(raw: RawFd) -> Result<OwnedFd> {
    if raw < 0 {
        Err(refuse())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn c(raw: &[u8]) -> Result<CString> {
    CString::new(raw).map_err(err)
}
fn stat(raw: RawFd) -> Result<libc::stat> {
    let mut s = std::mem::MaybeUninit::uninit();
    if unsafe { libc::fstat(raw, s.as_mut_ptr()) } != 0 {
        return Err(refuse());
    }
    Ok(unsafe { s.assume_init() })
}
fn same(a: &libc::stat, b: &libc::stat) -> bool {
    a.st_dev == b.st_dev
        && a.st_ino == b.st_ino
        && a.st_uid == b.st_uid
        && a.st_gid == b.st_gid
        && a.st_mode == b.st_mode
        && a.st_nlink == b.st_nlink
        && a.st_size == b.st_size
        && a.st_mtime == b.st_mtime
        && a.st_mtime_nsec == b.st_mtime_nsec
        && a.st_ctime == b.st_ctime
        && a.st_ctime_nsec == b.st_ctime_nsec
}
fn open_regular(path: &Path) -> Result<OwnedFd> {
    let raw = fd(unsafe {
        libc::open(
            c(path.as_os_str().as_bytes())?.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    })?;
    let s = stat(raw.as_raw_fd())?;
    if s.st_mode & libc::S_IFMT != libc::S_IFREG || s.st_nlink != 1 || s.st_mode & 0o022 != 0 {
        return Err(refuse());
    }
    Ok(raw)
}
fn probe_main(path: &Path) -> Result<Option<(OwnedFd, libc::stat)>> {
    let raw = unsafe {
        libc::open(
            c(path.as_os_str().as_bytes())?.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(None)
        } else {
            Err(refuse())
        };
    }
    let held = fd(raw)?;
    let before = stat(held.as_raw_fd())?;
    if before.st_mode & libc::S_IFMT != libc::S_IFREG
        || before.st_nlink != 1
        || before.st_mode & 0o022 != 0
    {
        return Err(refuse());
    }
    Ok(Some((held, before)))
}
#[derive(Clone)]
struct Account {
    name: String,
    uid: u32,
    gid: u32,
    home: PathBuf,
}
fn passwd(bytes: &[u8]) -> Result<Vec<Account>> {
    if bytes.len() > 1024 * 1024 {
        return Err(refuse());
    }
    let text = std::str::from_utf8(bytes).map_err(err)?;
    let mut out = Vec::new();
    let mut names = BTreeMap::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7
            || fields[0].is_empty()
            || !fields[2].bytes().all(|b| b.is_ascii_digit())
            || !fields[3].bytes().all(|b| b.is_ascii_digit())
        {
            return Err(refuse());
        }
        let uid = fields[2].parse::<u32>().map_err(err)?;
        let gid = fields[3].parse::<u32>().map_err(err)?;
        let home = PathBuf::from(fields[5]);
        if !home.is_absolute()
            || home.components().any(|p| {
                !matches!(
                    p,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || home.components().collect::<PathBuf>().as_os_str() != home.as_os_str()
        {
            return Err(refuse());
        }
        if names.insert(fields[0].to_string(), uid).is_some() {
            return Err(refuse());
        }
        out.push(Account {
            name: fields[0].into(),
            uid,
            gid,
            home,
        });
        if out.len() > 16384 {
            return Err(refuse());
        }
    }
    Ok(out)
}
fn named<'a>(accounts: &'a [Account], name: &str) -> Result<&'a Account> {
    let mut matches = accounts.iter().filter(|a| a.name == name);
    let a = matches.next().ok_or_else(refuse)?;
    if matches.next().is_some() {
        return Err(refuse());
    }
    Ok(a)
}
fn closed_service(accounts: &[Account], uid: u32) -> Result<u32> {
    let matches: Vec<_> = accounts
        .iter()
        .filter(|a| matches!(a.name.as_str(), "root" | "aegis" | "aegis-svc") && a.uid == uid)
        .collect();
    if matches.len() != 1 {
        return Err(refuse());
    }
    if matches[0].name == "root" && uid != 0 {
        return Err(refuse());
    }
    Ok(matches[0].uid)
}
fn one(input: &CapturedInput) -> Result<&[u8]> {
    let CapturedInput::Present(t) = input else {
        return Err(refuse());
    };
    let mut values = t.entries();
    let value = values.next().ok_or_else(refuse)?.1;
    if values.next().is_some() {
        return Err(refuse());
    }
    Ok(value)
}
fn limited() -> CaptureLimits {
    CaptureLimits {
        depth: 8,
        files: 1,
        directories: 1,
        file_bytes: 1024 * 1024,
        tree_bytes: 1024 * 1024,
    }
}
fn capture_file(path: &Path, role: InputRole) -> Result<CapturedInput> {
    CapturedTree::capture_optional(
        path,
        path.parent().ok_or_else(refuse)?.into(),
        role,
        limited(),
        false,
    )
    .map_err(err)
}
fn endpoint(value: &str) -> Result<(String, u16, Option<IpAddr>)> {
    let (host, port) = value.rsplit_once(':').ok_or_else(refuse)?;
    let port = port.parse::<u16>().map_err(err)?;
    if port == 0 || host.is_empty() || host.len() > 253 {
        return Err(refuse());
    }
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((host.into(), port, Some(ip)));
    }
    if !host
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-'))
        || host.starts_with('-')
    {
        return Err(refuse());
    }
    Ok((host.into(), port, None))
}
fn trusted_executable(path: &Path) -> Result<OwnedFd> {
    let f = open_regular(path)?;
    let s = stat(f.as_raw_fd())?;
    if s.st_uid != 0 || s.st_mode & 0o111 == 0 {
        return Err(refuse());
    }
    Ok(f)
}
fn reap_bounded(child: &mut std::process::Child) -> Result<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(1);
    loop {
        if let Some(s) = child.try_wait().map_err(err)? {
            return Ok(s);
        }
        if Instant::now() >= deadline {
            return Err(refuse());
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn kill_owned_group(child: &mut std::process::Child) {
    if let Ok(pid) = i32::try_from(child.id()) {
        unsafe { libc::kill(-pid, libc::SIGKILL) };
    }
    let _ = reap_bounded(child);
}
fn reap_before(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Result<std::process::ExitStatus> {
    loop {
        if Instant::now() >= deadline {
            return Err(refuse());
        }
        if let Some(s) = child.try_wait().map_err(err)? {
            if Instant::now() >= deadline {
                return Err(refuse());
            }
            return Ok(s);
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
/// Run one already selected child with a hard active deadline. The process
/// group bounds explicit cleanup; the parent-death signal covers the direct
/// getent process if the caller disappears unexpectedly.
fn bounded_child_output(mut command: Command, active_limit: Duration) -> Result<Vec<u8>> {
    let parent_pid = unsafe { libc::getpid() };
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .process_group(0);
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Ok(())
        });
    }
    let deadline = Instant::now() + active_limit;
    let mut child = command.spawn().map_err(err)?;
    let mut output = match child.stdout.take() {
        Some(p) => p,
        None => {
            kill_owned_group(&mut child);
            return Err(refuse());
        }
    };
    let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        kill_owned_group(&mut child);
        return Err(refuse());
    }
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        if Instant::now() >= deadline {
            kill_owned_group(&mut child);
            return Err(refuse());
        }
        match output.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => {
                if bytes.len() + n > 65536 {
                    kill_owned_group(&mut child);
                    return Err(refuse());
                }
                bytes.extend_from_slice(&buffer[..n]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => (),
            Err(_) => {
                kill_owned_group(&mut child);
                return Err(refuse());
            }
        }
    }
    // EOF can arrive while the child is still alive. Never accept output until
    // the process exits, and never let the post-EOF wait extend its deadline.
    let eof_deadline = std::cmp::min(deadline, Instant::now() + Duration::from_secs(1));
    let status = match reap_before(&mut child, eof_deadline) {
        Ok(s) => s,
        Err(e) => {
            kill_owned_group(&mut child);
            return Err(e);
        }
    };
    if Instant::now() >= deadline {
        kill_owned_group(&mut child);
        return Err(refuse());
    }
    if !status.success() {
        kill_owned_group(&mut child);
        return Err(refuse());
    }
    Ok(bytes)
}
/// One actual IPv4 DNS observation, bounded both process lifetime and stdout.
/// Fixed executable argv only. This is not a target network/privacy acceptance.
fn resolve_once(host: &str) -> Result<Ipv4Addr> {
    let _getent = trusted_executable(Path::new("/usr/bin/getent"))?;
    let mut command = Command::new("/usr/bin/getent");
    command.args(["-s", "dns", "ahostsv4", host]);
    dns_result(&bounded_child_output(command, Duration::from_secs(3))?)
}
fn dns_result(bytes: &[u8]) -> Result<Ipv4Addr> {
    let text = std::str::from_utf8(bytes).map_err(err)?;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let Some(ip) = words.next() else {
            continue;
        };
        let Some(kind) = words.next() else {
            return Err(refuse());
        };
        if !matches!(kind, "STREAM" | "DGRAM" | "RAW") {
            return Err(refuse());
        }
        return ip.parse::<Ipv4Addr>().map_err(err);
    }
    Err(refuse())
}
struct StageParent {
    parent: OwnedFd,
    root: OwnedFd,
    initial: libc::stat,
}
impl StageParent {
    fn revalidate(&self) -> Result<()> {
        let named_parent = fd(unsafe {
            libc::open(
                c(b"/run")?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let expected_parent = stat(self.parent.as_raw_fd())?;
        let actual_parent = stat(named_parent.as_raw_fd())?;
        if expected_parent.st_dev != actual_parent.st_dev
            || expected_parent.st_ino != actual_parent.st_ino
            || actual_parent.st_uid != 0
            || actual_parent.st_mode & 0o022 != 0
        {
            return Err(refuse());
        }
        let held = stat(self.root.as_raw_fd())?;
        let leaf = c(b"aegis-installer-config-snapshots")?;
        let named = fd(unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let current = stat(named.as_raw_fd())?;
        if held.st_dev != self.initial.st_dev
            || held.st_ino != self.initial.st_ino
            || current.st_dev != held.st_dev
            || current.st_ino != held.st_ino
            || held.st_uid != 0
            || held.st_gid != 0
            || held.st_mode & 0o7777 != 0o700
        {
            return Err(refuse());
        }
        Ok(())
    }
}
fn staging_parent(path: &Path) -> Result<StageParent> {
    if path != Path::new("/run/aegis-installer-config-snapshots") {
        return Err(refuse());
    }
    let run = fd(unsafe {
        libc::open(
            c(b"/run")?.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    let rs = stat(run.as_raw_fd())?;
    if rs.st_uid != 0 || rs.st_mode & libc::S_IFMT != libc::S_IFDIR || rs.st_mode & 0o022 != 0 {
        return Err(refuse());
    }
    let name = c(b"aegis-installer-config-snapshots")?;
    let mut created = false;
    let root = match fd(unsafe {
        libc::openat(
            run.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    }) {
        Ok(f) => f,
        Err(_) if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) => {
            // Retain independent public metadata intent under trusted root-owned/run
            // before the fixed new parent, never delete or adopt arbitrary entries.
            let random: [u8; 16] = rand::random();
            let receipt_name = format!(".aegis-stage-parent-{}.json", hex::encode(random));
            let record = fd(unsafe {
                libc::openat(
                    run.as_raw_fd(),
                    c(receipt_name.as_bytes())?.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC,
                    0o600,
                )
            })?;
            let mut intent = File::from(record);
            let bytes=serde_json::to_vec(&serde_json::json!({"schema":1,"target":"/run/aegis-installer-config-snapshots","parent_dev":rs.st_dev,"parent_ino":rs.st_ino,"new_uid":0,"new_gid":0,"new_mode":448})).map_err(err)?;
            intent
                .write_all(&bytes)
                .and_then(|_| intent.sync_all())
                .map_err(err)?;
            if unsafe { libc::fsync(run.as_raw_fd()) } != 0 {
                return Err(refuse());
            }
            if unsafe { libc::mkdirat(run.as_raw_fd(), name.as_ptr(), 0o700) } != 0 {
                return Err(refuse());
            }
            created = true;
            fd(unsafe {
                libc::openat(
                    run.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?
        }
        Err(e) => return Err(e),
    };
    if created
        && (unsafe { libc::fchown(root.as_raw_fd(), 0, 0) } != 0
            || unsafe { libc::fchmod(root.as_raw_fd(), 0o700) } != 0)
    {
        return Err(refuse());
    }
    let initial = stat(root.as_raw_fd())?;
    let out = StageParent {
        parent: run,
        root,
        initial,
    };
    out.revalidate()?;
    if unsafe { libc::fsync(out.parent.as_raw_fd()) } != 0 {
        return Err(refuse());
    }
    Ok(out)
}

pub(super) struct HeldAdmission {
    main: CapturedInput,
    passwd: CapturedInput,
    markers: Vec<CapturedInput>,
    probe: Option<(OwnedFd, libc::stat)>,
    stage_parent: StageParent,
    choice: ExistingChoice,
    existing: bool,
    ipv6: bool,
    main_bytes: zeroize::Zeroizing<Vec<u8>>,
}
impl HeldAdmission {
    pub(super) fn revalidate_after_prepare(
        &self,
        prepared: &prepare::PreparedInputs,
    ) -> Result<()> {
        self.main.revalidate_original_generation().map_err(err)?;
        self.passwd.revalidate_original_generation().map_err(err)?;
        for marker in &self.markers {
            marker.revalidate_original_generation().map_err(err)?;
        }
        if let Some((fd, before)) = &self.probe {
            if !same(before, &stat(fd.as_raw_fd())?) {
                return Err(refuse());
            }
        }
        self.stage_parent.revalidate()?;
        if prepared.is_upgrade != self.existing
            || matches!(self.choice, ExistingChoice::None) == prepared.is_upgrade
            || (self.ipv6 && prepared.mode != "socks-only")
        {
            return Err(refuse());
        }
        let role = if self.existing {
            crate::profile_auto_prepare::Role::Config
        } else {
            crate::profile_auto_prepare::Role::BundleMain
        };
        let selected = prepared.raw.get(&role).ok_or_else(refuse)?;
        let filename = if self.existing {
            Path::new("aegis.toml")
        } else {
            Path::new("aegis-client.toml")
        };
        if selected.files.get(filename).ok_or_else(refuse)?.as_slice() != self.main_bytes.as_slice()
        {
            return Err(refuse());
        }
        prepared.revalidate_originals().map_err(err)
    }
}
#[cfg(target_os = "linux")]
pub(super) fn prepare_request(args: &PrepareArgs) -> Result<(prepare::Request, HeldAdmission)> {
    if unsafe { libc::geteuid() } != 0 || args.udp_carry {
        return Err(refuse());
    }
    let passwd_capture = capture_file(
        Path::new("/etc/passwd"),
        InputRole::AdministratorMetadata {
            administrator_uid: 0,
        },
    )?;
    let accounts = passwd(one(&passwd_capture)?)?;
    let root = named(&accounts, "root")?;
    if root.uid != 0 || root.gid != 0 {
        return Err(refuse());
    }
    let main_path = args.config_root.join("aegis.toml");
    let probe = probe_main(&main_path)?;
    let existing = probe.is_some();
    if matches!(args.existing_choice, ExistingChoice::None) == existing {
        return Err(refuse());
    }
    let service_uid = if let Some((_, before)) = &probe {
        closed_service(&accounts, before.st_uid)?
    } else {
        0
    };
    let operator_uid = if args.bundle_dir.is_some() {
        match std::env::var("SUDO_UID") {
            Ok(s) if !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()) => {
                s.parse::<u32>().map_err(err)?
            }
            Ok(_) => return Err(refuse()),
            Err(std::env::VarError::NotPresent) => 0,
            Err(_) => return Err(refuse()),
        }
    } else {
        0
    };
    if !accounts.iter().any(|a| a.uid == operator_uid) {
        return Err(refuse());
    }
    let chosen = if existing {
        main_path
    } else {
        args.bundle_dir
            .as_ref()
            .ok_or_else(refuse)?
            .join("aegis-client.toml")
    };
    let role = if existing {
        InputRole::ServiceInput {
            service_uid,
            administrator_uid: 0,
        }
    } else {
        InputRole::ExplicitBundleData {
            operator_uid,
            administrator_uid: 0,
        }
    };
    let main_limits = CaptureLimits {
        depth: 8,
        files: 1,
        directories: 1,
        file_bytes: 4 * 1024 * 1024,
        tree_bytes: 4 * 1024 * 1024,
    };
    let main = if existing {
        CapturedTree::capture_optional_service_file(
            &chosen,
            &args.config_root,
            args.config_root.clone(),
            role,
            main_limits,
        )
    } else {
        CapturedTree::capture_optional(
            &chosen,
            chosen.parent().ok_or_else(refuse)?.into(),
            role,
            main_limits,
            false,
        )
    }
    .map_err(err)?;
    let main_bytes = zeroize::Zeroizing::new(one(&main)?.to_vec());
    let settings: Settings =
        toml::from_str(std::str::from_utf8(&main_bytes).map_err(err)?).map_err(err)?;
    if crate::profile_auto::validate_auto_relay_auth(&settings).is_err() {
        return Err(refuse());
    }
    let mut markers = Vec::new();
    for leaf in [
        "wide-profile.json",
        "operator-mode.json",
        "install-manifest.json",
    ] {
        markers.push(capture_file(
            &args.metadata_dir.join(leaf),
            InputRole::AdministratorMetadata {
                administrator_uid: 0,
            },
        )?);
    }
    let prior_native_markers = markers
        .iter()
        .any(|m| matches!(m, CapturedInput::Present(_)))
        || (existing
            && std::str::from_utf8(&main_bytes)
                .map_err(err)?
                .lines()
                .any(|line| line.trim_start().starts_with("# aegis-operator-mode:")));
    let (host, port, ip) = endpoint(&settings.relay.server)?;
    let ipv6 = matches!(ip, Some(IpAddr::V6(_)));
    let pin = match ip {
        Some(IpAddr::V4(addr)) => Some(RelayPin {
            original: settings.relay.server.clone(),
            selected: SocketAddrV4::new(addr, port),
        }),
        Some(IpAddr::V6(_)) => None,
        None => Some(RelayPin {
            original: settings.relay.server.clone(),
            selected: SocketAddrV4::new(resolve_once(&host)?, port),
        }),
    };
    let stage_parent = staging_parent(&args.staging_parent)?;
    // Same root passwd home as old installer's root os.path.expanduser authority,
    // not operator bundle owner/service HOME or arbitrary environment HOME.
    let request = prepare::Request {
        config_root: args.config_root.clone(),
        state_target: args.state_dir.clone(),
        metadata_target: args.metadata_dir.clone(),
        bundle: args.bundle_dir.clone(),
        service_uid,
        operator_uid,
        admitted_home: Some(root.home.clone()),
        wide_interface: args.wide_interface.clone(),
        relay_pin: pin,
        masque_server: args.masque_server.clone(),
        explicit_masque_ca: args.masque_ca.clone(),
        prior_native_markers,
        requested_mode: args.requested_mode.clone(),
    };
    Ok((
        request,
        HeldAdmission {
            main,
            passwd: passwd_capture,
            markers,
            probe,
            stage_parent,
            choice: args.existing_choice,
            existing,
            ipv6,
            main_bytes,
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "linux")]
    fn assert_child_not_running(pid_path: &Path) {
        let pid: u32 = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
        for _ in 0..50 {
            let path = format!("/proc/{pid}/stat");
            match std::fs::read_to_string(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Ok(stat)
                    if stat
                        .rsplit_once(") ")
                        .is_some_and(|(_, tail)| tail.starts_with('Z')) =>
                {
                    return
                }
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        panic!("owned child remained running after bounded refusal");
    }
    #[test]
    fn actual_passwd_shape_and_closed_service_names_are_required() {
        let users=passwd(b"root:x:0:0:root:/root:/bin/sh\naegis:x:991:991:aegis:/var/lib/aegis:/usr/sbin/nologin\noperator:x:1000:1000:user:/home/operator:/bin/sh\n").unwrap();
        assert_eq!(closed_service(&users, 0).unwrap(), 0);
        assert_eq!(closed_service(&users, 991).unwrap(), 991);
        assert!(closed_service(&users, 1000).is_err());
        assert_eq!(named(&users, "root").unwrap().home, Path::new("/root"));
        assert!(passwd(b"root:x:0:0:root:/root/../tmp:/bin/sh\n").is_err());
    }
    #[test]
    fn endpoint_ipv4_ipv6_and_dns_observations_have_explicit_types() {
        assert!(matches!(
            endpoint("203.0.113.7:443").unwrap().2,
            Some(IpAddr::V4(_))
        ));
        assert!(matches!(
            endpoint("[2001:db8::1]:443").unwrap().2,
            Some(IpAddr::V6(_))
        ));
        assert!(endpoint("relay.example:443").unwrap().2.is_none());
        assert!(endpoint("--injected:443").is_err());
    }
    #[test]
    fn bounded_getent_observation_accepts_only_actual_ipv4_tokens() {
        assert_eq!(
            dns_result(b"203.0.113.7 STREAM relay.example\n203.0.113.7 DGRAM\n").unwrap(),
            Ipv4Addr::new(203, 0, 113, 7)
        );
        assert!(dns_result(b"2001:db8::1 STREAM host\n").is_err());
        assert!(dns_result(b"arbitrary payload\n").is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_child_accepts_output_and_sets_parent_death_signal() {
        let mut child = Command::new("/usr/bin/python3");
        child.args(["-c", "import ctypes; v=ctypes.c_int(); r=ctypes.CDLL(None).prctl(2,ctypes.byref(v),0,0,0); print(r,v.value)"]);
        assert_eq!(
            bounded_child_output(child, Duration::from_secs(1)).unwrap(),
            format!("0 {}\n", libc::SIGKILL).into_bytes()
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_child_refuses_eof_before_exit_and_oversized_stdout() {
        let mut close_then_hang = Command::new("/usr/bin/python3");
        close_then_hang.args(["-c", "import os,time;os.close(1);time.sleep(5)"]);
        let started = Instant::now();
        assert!(bounded_child_output(close_then_hang, Duration::from_millis(100)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));

        let mut oversize = Command::new("/usr/bin/python3");
        oversize.args([
            "-c",
            "import sys;sys.stdout.buffer.write(b'x'*65537);sys.stdout.flush()",
        ]);
        assert!(bounded_child_output(oversize, Duration::from_secs(1)).is_err());
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_child_kills_owned_group_when_descendant_holds_stdout() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("descendant.pid");
        let mut descendant = Command::new("/bin/sh");
        descendant.args([
            "-c",
            "sleep 5 & printf '%s' \"$!\" > \"$1\"; exit 0",
            "sh",
            pid_path.to_str().unwrap(),
        ]);
        let started = Instant::now();
        assert!(bounded_child_output(descendant, Duration::from_millis(500)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_child_not_running(&pid_path);
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn bounded_child_kills_owned_group_after_nonzero_exit() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("descendant.pid");
        let mut descendant = Command::new("/bin/sh");
        descendant.args([
            "-c",
            "sleep 5 >/dev/null 2>&1 & printf '%s' \"$!\" > \"$1\"; exit 7",
            "sh",
            pid_path.to_str().unwrap(),
        ]);
        let started = Instant::now();
        assert!(bounded_child_output(descendant, Duration::from_secs(5)).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_child_not_running(&pid_path);
    }
    #[test]
    fn duplicate_closed_accounts_or_wrong_root_uid_refuse() {
        assert!(passwd(b"root:x:0:0::/root:/bin/sh\nroot:x:0:0::/root:/bin/sh\n").is_err());
        let users = passwd(b"root:x:1:0::/root:/bin/sh\n").unwrap();
        assert!(closed_service(&users, 0).is_err());
    }
}
