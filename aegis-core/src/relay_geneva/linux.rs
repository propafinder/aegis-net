//! Linux owned relay-only NFQUEUE driver. No activation during compilation/tests.
//! Each complete validated batch replaces a DROPped original; no ACCEPT fallback.
//! Rules stay fail closed until all owned socket inodes disappear. Pre-existing
//! host routes/interfaces/filtering stay unchanged; one owned local alias only.
use super::{
    installed_guard::{self, InstalledGuardProof},
    installed_profile::InstalledGuardAuthorization,
    queue::{self, Hook, QueuePin},
    stream::RelaySocketGuard,
    RelayFlowPin, RelayGenevaProgram, RelayOuterGenevaSettings, RelayPacketDirection,
};
use rand::RngCore;
use serde_json::Value;
use sha2::Digest;
use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet, VecDeque},
    io::{self, Read, Write},
    net::{Ipv4Addr, SocketAddrV4},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::process::CommandExt,
    },
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::net::{TcpSocket, TcpStream};
const MAX_FLOWS: usize = 128;
const MAX_LIFETIME_FLOWS: u64 = 1024;
const QUEUE_LIMIT: usize = 256;
const MAX_COMMAND_BYTES: usize = 524288;
thread_local! {static COMMAND_JOURNAL:RefCell<Option<Arc<Journal>>>=const{RefCell::new(None)};}
use super::operation_deadline::Scope as OperationBudget;

struct JournalScope(Option<Arc<Journal>>);
impl JournalScope {
    fn enter(journal: &Arc<Journal>) -> Self {
        Self(COMMAND_JOURNAL.with(|slot| slot.replace(Some(Arc::clone(journal)))))
    }
}
impl Drop for JournalScope {
    fn drop(&mut self) {
        COMMAND_JOURNAL.with(|slot| {
            slot.replace(self.0.take());
        });
    }
}
fn command_failure_evidence(
    program: &str,
    args: &[&str],
    phase: &str,
    output: &[u8],
    errors: &[u8],
) {
    COMMAND_JOURNAL.with(|slot|{if let Some(journal)=slot.borrow().as_ref(){let arg_hash=sha2::Sha256::digest(args.join("\0").as_bytes());let _=journal.record("native_command_failed",serde_json::json!({"program":program,"argument_sha256":hex::encode(arg_hash),"phase":phase,"stdout_sha256":hex::encode(sha2::Sha256::digest(output)),"stderr_sha256":hex::encode(sha2::Sha256::digest(errors)),"stderr_prefix_hex":hex::encode(&errors[..errors.len().min(16384)]),"stderr_prefix_truncated":errors.len()>16384,"command_input_not_saved":true}));}});
}

fn operation_live() -> io::Result<()> {
    super::operation_deadline::check()
}
fn finite_deadline(duration: Duration) -> Instant {
    super::operation_deadline::bounded(duration)
}
fn nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0,
        "owned helper nonblocking pipe refused",
    )
}

fn refuse(message: &str) -> io::Error {
    io::Error::other(message)
}
fn ensure(ok: bool, message: &str) -> io::Result<()> {
    if ok {
        Ok(())
    } else {
        Err(refuse(message))
    }
}
fn lock<T>(m: &Mutex<T>) -> io::Result<std::sync::MutexGuard<'_, T>> {
    m.lock().map_err(|_| refuse("relay worker lock poisoned"))
}
fn owned_fd(raw: i32) -> io::Result<OwnedFd> {
    if raw < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn option<T>(fd: i32, kind: i32, value: &T) -> io::Result<()> {
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            kind,
            (value as *const T).cast(),
            std::mem::size_of::<T>() as u32,
        )
    };
    ensure(result == 0, "owned socket option refused")
}
/// Owns a child until it is reaped. Failure paths keep the unreaped PID pinned;
/// a pidfd signal never follows numeric PID reuse.
struct OwnedCommand {
    child: std::process::Child,
    pidfd: OwnedFd,
    reaped: bool,
}
impl std::ops::Deref for OwnedCommand {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.child
    }
}
impl std::ops::DerefMut for OwnedCommand {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.child
    }
}
impl OwnedCommand {
    fn wait_owned(&mut self) -> io::Result<std::process::ExitStatus> {
        let status = self.child.wait()?;
        self.reaped = true;
        Ok(status)
    }
}
fn can_signal_group(unreaped: bool, waitid_ok: bool, exact_group: bool) -> bool {
    unreaped && waitid_ok && exact_group
}
impl Drop for OwnedCommand {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        let pid = self.child.id() as i32;
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let owned = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                self.pidfd.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } == 0;
        if can_signal_group(true, owned, unsafe { libc::getpgid(pid) } == pid) {
            unsafe {
                libc::kill(-pid, libc::SIGKILL);
            }
        } else {
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        let deadline = Instant::now() + Duration::from_millis(250);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = true;
                    break;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
                _ => break,
            }
        }
    }
}
/// Separate process group, finite commands, bounded stdout/stderr. Never a shell.
#[derive(Clone)]
struct ToolPin {
    path: std::path::PathBuf,
    inode: u64,
    device: u64,
    hash: [u8; 32],
}
static TOOLS: OnceLock<BTreeMap<String, ToolPin>> = OnceLock::new();
fn tool_pin(path: &std::path::Path) -> io::Result<ToolPin> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let canonical = std::fs::canonicalize(path)?;
    let metadata = std::fs::metadata(&canonical)?;
    ensure(
        metadata.len() <= 134217728
            && metadata.is_file()
            && metadata.uid() == 0
            && metadata.permissions().mode() & 0o022 == 0
            && metadata.permissions().mode() & 0o111 != 0,
        "native helper executable not trusted",
    )?;
    for parent in canonical.ancestors().skip(1) {
        let m = std::fs::metadata(parent)?;
        ensure(
            m.is_dir() && m.uid() == 0 && m.permissions().mode() & 0o022 == 0,
            "native helper parent writable/unowned",
        )?;
    }
    let hash: [u8; 32] = Sha256::digest(std::fs::read(&canonical)?).into();
    Ok(ToolPin {
        path: canonical,
        inode: metadata.ino(),
        device: metadata.dev(),
        hash,
    })
}
fn trusted_tools() -> io::Result<&'static BTreeMap<String, ToolPin>> {
    if let Some(p) = TOOLS.get() {
        return Ok(p);
    }
    let mut pins = BTreeMap::new();
    for name in ["ip", "nft"] {
        let pin = ["/usr/sbin", "/usr/bin", "/sbin", "/bin"]
            .into_iter()
            .find_map(|parent| tool_pin(&std::path::Path::new(parent).join(name)).ok())
            .ok_or_else(|| refuse("trusted canonical native helper unavailable"))?;
        pins.insert(name.to_string(), pin);
    }
    let _ = TOOLS.set(pins);
    TOOLS
        .get()
        .ok_or_else(|| refuse("native tool pin unavailable"))
}
fn command(program: &str, args: &[&str], input: Option<&[u8]>) -> io::Result<Vec<u8>> {
    command_checked(program, args, input, |_, _| Ok(()))
}
fn command_checked(
    program: &str,
    args: &[&str],
    input: Option<&[u8]>,
    mut completed: impl FnMut(u32, &str) -> io::Result<()>,
) -> io::Result<Vec<u8>> {
    operation_live()?;
    let deadline = finite_deadline(Duration::from_secs(3));
    ensure(
        input.is_none_or(|v| v.len() <= 65536),
        "command input bound",
    )?;
    let pins = trusted_tools()?;
    let pin = pins
        .get(program)
        .ok_or_else(|| refuse("unapproved native helper"))?;
    let fresh = tool_pin(&pin.path)?;
    ensure(
        fresh.inode == pin.inode && fresh.device == pin.device && fresh.hash == pin.hash,
        "native executable pin drift",
    )?;
    operation_live()?;
    let mut builder = Command::new(&pin.path);
    builder
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let parent = unsafe { libc::getpid() };
    unsafe {
        builder.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 || libc::getppid() != parent {
                return Err(io::Error::other("native helper parent binding refused"));
            }
            if libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = builder.spawn()?;
    let pid = child.id() as i32;
    let pidfd = match owned_fd(unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as i32 }) {
        Ok(fd) => fd,
        Err(error) => {
            let _ = child.kill();
            let stop = Instant::now() + Duration::from_millis(250);
            while Instant::now() < stop {
                if child.try_wait().ok().flatten().is_some() {
                    break;
                }
                thread::sleep(Duration::from_millis(2));
            }
            return Err(error);
        }
    };
    let mut child = OwnedCommand {
        child,
        pidfd,
        reaped: false,
    };
    let mut stdout = child.stdout.take().ok_or_else(|| refuse("stdout absent"))?;
    let mut stderr = child.stderr.take().ok_or_else(|| refuse("stderr absent"))?;
    let mut stdin = child.stdin.take();
    nonblocking(stdout.as_raw_fd())?;
    nonblocking(stderr.as_raw_fd())?;
    nonblocking(
        stdin
            .as_ref()
            .ok_or_else(|| refuse("stdin absent"))?
            .as_raw_fd(),
    )?;
    let data = input.unwrap_or_default();
    let mut sent = 0usize;
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let mut output_end = false;
    let mut error_end = false;
    let mut scratch = [0; 8192];
    loop {
        for (reader, bytes, ended) in [
            (&mut stdout as &mut dyn Read, &mut output, &mut output_end),
            (&mut stderr as &mut dyn Read, &mut errors, &mut error_end),
        ] {
            if !*ended {
                loop {
                    match reader.read(&mut scratch) {
                        Ok(0) => {
                            *ended = true;
                            break;
                        }
                        Ok(n) => {
                            ensure(
                                bytes.len() + n <= MAX_COMMAND_BYTES,
                                "owned command output bound",
                            )?;
                            bytes.extend_from_slice(&scratch[..n]);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
            }
        }
        if let Some(writer) = stdin.as_mut() {
            if sent == data.len() {
                stdin = None
            } else {
                match writer.write(&data[sent..]) {
                    Ok(0) => return Err(refuse("native helper stdin ended")),
                    Ok(n) => sent += n,
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                child.pidfd.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        } else if unsafe { info.si_pid() } != 0 {
            break;
        }
        if Instant::now() >= deadline {
            command_failure_evidence(program, args, "deadline", &output, &errors);
            return Err(refuse("owned native helper total deadline"));
        }
        thread::sleep(Duration::from_millis(2));
    }
    // Notification attribution must happen BEFORE wait/reap: the exact pidfd child
    // pins the PID while generation/element receipts are consumed.
    let actor_name = std::path::Path::new(&pin.path)
        .file_name()
        .and_then(|v| v.to_str())
        .ok_or_else(|| refuse("helper actor name refused"))?;
    ensure(actor_name.is_ascii(), "helper actor name encoding refused")?;
    completed(pid as u32, &actor_name[..actor_name.len().min(15)])?;
    // Still unreaped: numeric group cannot be reused while this exact child pins it.
    ensure(
        can_signal_group(!child.reaped, true, unsafe { libc::getpgid(pid) } == pid),
        "owned helper session binding failed",
    )?;
    let kill = unsafe { libc::kill(-pid, libc::SIGKILL) };
    ensure(
        kill == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH),
        "owned helper group termination refused",
    )?;
    let status = child.wait_owned()?;
    // Drain the now-terminated owned group; no joining pipe threads or descendants.
    let drain = finite_deadline(Duration::from_millis(100));
    while !output_end || !error_end {
        for (reader, bytes, ended) in [
            (&mut stdout as &mut dyn Read, &mut output, &mut output_end),
            (&mut stderr as &mut dyn Read, &mut errors, &mut error_end),
        ] {
            if !*ended {
                match reader.read(&mut scratch) {
                    Ok(0) => *ended = true,
                    Ok(n) => {
                        ensure(
                            bytes.len() + n <= MAX_COMMAND_BYTES,
                            "owned command output bound",
                        )?;
                        bytes.extend_from_slice(&scratch[..n]);
                    }
                    Err(e)
                        if e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(e),
                }
            }
        }
        ensure(
            Instant::now() < drain || output_end && error_end,
            "owned helper pipe terminal deadline",
        )?;
        if !output_end || !error_end {
            thread::sleep(Duration::from_millis(2));
        }
    }
    operation_live()?;
    if !status.success() {
        command_failure_evidence(program, args, "nonzero_status", &output, &errors);
        return Err(refuse("owned native command refused"));
    }
    Ok(output)
}
fn json(program: &str, args: &[&str]) -> io::Result<Value> {
    serde_json::from_slice(&command(program, args, None)?)
        .map_err(|_| refuse("native metadata schema refused"))
}
fn parse_mac(text: &str) -> io::Result<[u8; 6]> {
    let values = text
        .split(':')
        .map(|v| u8::from_str_radix(v, 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| refuse("MAC metadata refused"))?;
    values.try_into().map_err(|_| refuse("MAC width refused"))
}
#[derive(Clone)]
struct RouteProof {
    ifindex: u32,
    mtu: usize,
    via: Ipv4Addr,
}
fn route(
    request: &RelayOuterGenevaSettings,
    endpoint: SocketAddrV4,
    port: Option<u16>,
) -> io::Result<RouteProof> {
    let mark = request.socket_mark.to_string();
    let destination = endpoint.ip().to_string();
    let local = request.local_address.to_string();
    let dport = endpoint.port().to_string();
    let sport = port.map(|p| p.to_string());
    let mut args = vec![
        "-j",
        "route",
        "get",
        &destination,
        "from",
        &local,
        "mark",
        &mark,
        "ipproto",
        "tcp",
        "dport",
        &dport,
    ];
    if let Some(value) = &sport {
        args.extend(["sport", value]);
    }
    let data = json("ip", &args)?;
    let rows = data.as_array().ok_or_else(|| refuse("route rows absent"))?;
    ensure(rows.len() == 1, "route ambiguous")?;
    let row = &rows[0];
    ensure(
        row.get("dev").and_then(Value::as_str) == Some(&request.interface),
        "relay route leaves pinned interface",
    )?;
    if let Some(value) = row.get("prefsrc").or_else(|| row.get("src")) {
        ensure(value.as_str() == Some(&local), "relay route source drift")?;
    }
    let via = row
        .get("gateway")
        .and_then(Value::as_str)
        .map(str::parse)
        .transpose()
        .map_err(|_| refuse("gateway metadata refused"))?
        .unwrap_or(*endpoint.ip());
    let link = json("ip", &["-j", "link", "show", "dev", &request.interface])?;
    let links = link
        .as_array()
        .ok_or_else(|| refuse("link schema refused"))?;
    ensure(links.len() == 1, "link ambiguous")?;
    let link = &links[0];
    ensure(
        link.get("address")
            .and_then(Value::as_str)
            .map(parse_mac)
            .transpose()?
            == Some(request.local_mac),
        "local MAC drift",
    )?;
    ensure(
        link.get("flags")
            .and_then(Value::as_array)
            .is_some_and(|v| v.iter().any(|s| s.as_str() == Some("UP"))),
        "pinned link not up",
    )?;
    let ifindex = link
        .get("ifindex")
        .and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| refuse("ifindex refused"))?;
    let mtu = link
        .get("mtu")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| refuse("MTU refused"))?;
    ensure(
        ifindex > 0 && (576..=65535).contains(&mtu),
        "native route bounds",
    )?;
    let addresses = json("ip", &["-j", "address", "show", "dev", &request.interface])?;
    ensure(
        addresses.as_array().is_some_and(|rows| {
            rows.iter().any(|row| {
                row.get("addr_info")
                    .and_then(Value::as_array)
                    .is_some_and(|info| {
                        info.iter()
                            .any(|v| v.get("local").and_then(Value::as_str) == Some(&local))
                    })
            })
        }),
        "source IPv4 not on pinned interface",
    )?;
    let target = via.to_string();
    let neighbors = json(
        "ip",
        &[
            "-j",
            "neigh",
            "show",
            "to",
            &target,
            "dev",
            &request.interface,
        ],
    )?;
    let neighbors = neighbors
        .as_array()
        .ok_or_else(|| refuse("neighbor schema refused"))?;
    ensure(neighbors.len() == 1, "next hop unresolved/ambiguous")?;
    ensure(
        neighbors[0]
            .get("lladdr")
            .and_then(Value::as_str)
            .map(parse_mac)
            .transpose()?
            == Some(request.next_hop_mac),
        "next hop MAC drift",
    )?;
    let states = neighbors[0]
        .get("state")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("neighbor state absent"))?;
    ensure(
        states.len() == 1
            && states[0].as_str().is_some_and(|s| {
                ["REACHABLE", "STALE", "DELAY", "PROBE", "PERMANENT"].contains(&s)
            }),
        "neighbor not usable",
    )?;
    Ok(RouteProof { ifindex, mtu, via })
}
fn attr(bytes: &mut Vec<u8>, kind: u16, data: &[u8]) {
    bytes.extend_from_slice(&((data.len() + 4) as u16).to_ne_bytes());
    bytes.extend_from_slice(&kind.to_ne_bytes());
    bytes.extend_from_slice(data);
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0)
    }
}
fn message(kind: u16, queue: u16, sequence: u32) -> Vec<u8> {
    let mut bytes = vec![0; 20];
    bytes[4..6].copy_from_slice(&kind.to_ne_bytes());
    bytes[6..8].copy_from_slice(&5u16.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes[16] = 2;
    bytes[18..20].copy_from_slice(&queue.to_be_bytes());
    bytes
}
fn finish(bytes: &mut [u8]) {
    let len = bytes.len() as u32;
    bytes[..4].copy_from_slice(&len.to_ne_bytes());
}
fn receive(fd: i32, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let count = unsafe {
        libc::poll(
            &mut poll,
            1,
            timeout.as_millis().min(i32::MAX as u128) as i32,
        )
    };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count == 0 {
        return Ok(None);
    }
    ensure(
        poll.revents & !(libc::POLLIN) == 0,
        "native queue poll failed",
    )?;
    let mut bytes = vec![0; 131072];
    let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut iov = libc::iovec {
        iov_base: bytes.as_mut_ptr().cast(),
        iov_len: bytes.len(),
    };
    let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
    header.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
    header.msg_namelen = std::mem::size_of::<libc::sockaddr_nl>() as u32;
    header.msg_iov = &mut iov;
    header.msg_iovlen = 1;
    let n = unsafe { libc::recvmsg(fd, &mut header, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    ensure(
        header.msg_flags & libc::MSG_TRUNC == 0
            && sender.nl_pid == 0
            && sender.nl_groups == 0
            && header.msg_namelen as usize == std::mem::size_of::<libc::sockaddr_nl>(),
        "NFQUEUE sender/truncation refused",
    )?;
    bytes.truncate(n as usize);
    Ok(Some(bytes))
}

static BUILD_SOURCE_STAMP: OnceLock<&'static str> = OnceLock::new();

fn bind_source_stamp(cell: &OnceLock<&'static str>, stamp: &'static str) -> io::Result<()> {
    ensure(
        stamp.len() == 40 && stamp.bytes().all(|c| c.is_ascii_hexdigit()),
        "native source provenance malformed",
    )?;
    if let Err(other) = cell.set(stamp) {
        ensure(
            cell.get() == Some(&other),
            "native source provenance already bound",
        )?;
    }
    Ok(())
}

/// Bind the executable crate's compile-time stamp once, before native work.
/// No runtime configuration or environment lookup can change this identity.
pub fn install_build_source_stamp(stamp: &'static str) -> io::Result<()> {
    bind_source_stamp(&BUILD_SOURCE_STAMP, stamp)
}

fn build_source_stamp() -> io::Result<&'static str> {
    BUILD_SOURCE_STAMP
        .get()
        .copied()
        .ok_or_else(|| refuse("native source provenance missing"))
}
fn local_netlink_port(fd: i32) -> io::Result<u32> {
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&address) as u32;
    ensure(
        unsafe {
            libc::getsockname(
                fd,
                (&mut address as *mut libc::sockaddr_nl).cast(),
                &mut length,
            )
        } == 0
            && length as usize == std::mem::size_of_val(&address)
            && address.nl_family == libc::AF_NETLINK as u16
            && address.nl_groups == 0
            && address.nl_pid != 0,
        "owned netlink port binding refused",
    )?;
    Ok(address.nl_pid)
}
fn exact_success_ack(reply: &[u8], request: &[u8], port: u32) -> bool {
    reply.len() == 36
        && request.len() >= 16
        && u32::from_ne_bytes(reply[0..4].try_into().unwrap()) == 36
        && u16::from_ne_bytes(reply[4..6].try_into().unwrap()) == 2
        && u16::from_ne_bytes(reply[6..8].try_into().unwrap()) & !0x100 == 0
        && reply[8..12] == request[8..12]
        && u32::from_ne_bytes(reply[12..16].try_into().unwrap()) == port
        && reply[16..20] == [0; 4]
        && reply[20..36] == request[..16]
}
fn own_link_request(ifindex: u32, name: &str, sequence: u32, ipv6: bool) -> io::Result<Vec<u8>> {
    ensure(
        ifindex > 0 && name.len() <= 15 && name.bytes().all(|c| c.is_ascii_alphanumeric()),
        "owned interface metadata refused",
    )?;
    let mut bytes = vec![0; 32];
    bytes[4..6].copy_from_slice(&16u16.to_ne_bytes());
    bytes[6..8].copy_from_slice(&5u16.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes[20..24].copy_from_slice(&ifindex.to_ne_bytes());

    let mut own_name = name.as_bytes().to_vec();
    own_name.push(0);
    attr(&mut bytes, 3, &own_name);
    attr(&mut bytes, 4, &65535u32.to_ne_bytes());
    let mut configuration = Vec::new();
    attr(&mut configuration, 8, &2u32.to_ne_bytes());
    let mut inet = Vec::new();
    attr(&mut inet, 0x8001, &configuration);
    let mut families = Vec::new();
    attr(&mut families, 0x8002, &inet);
    if ipv6 {
        let mut inet6 = Vec::new();
        attr(&mut inet6, 8, &[1]);
        attr(&mut families, 0x800a, &inet6);
    }
    attr(&mut bytes, 0x801a, &families);
    finish(&mut bytes);
    Ok(bytes)
}

fn own_route_ack(fd: i32, request: &[u8], port: u32) -> io::Result<()> {
    operation_live()?;
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    ensure(
        unsafe {
            libc::sendto(
                fd,
                request.as_ptr().cast(),
                request.len(),
                libc::MSG_DONTWAIT,
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        } == request.len() as isize,
        "owned TUN route configuration send refused",
    )?;
    let deadline = finite_deadline(Duration::from_millis(500));
    loop {
        ensure(
            Instant::now() < deadline,
            "owned TUN configuration ACK deadline",
        )?;
        if let Some(reply) = receive(fd, Duration::from_millis(5))? {
            ensure(
                exact_success_ack(&reply, request, port),
                "owned TUN configuration ACK refused",
            )?;
            return Ok(());
        }
    }
}
fn own_link_up_request(ifindex: u32, name: &str, sequence: u32) -> io::Result<Vec<u8>> {
    ensure(
        ifindex > 0 && name.len() <= 15 && name.bytes().all(|c| c.is_ascii_alphanumeric()),
        "owned interface metadata refused",
    )?;
    let mut bytes = vec![0; 32];
    bytes[4..6].copy_from_slice(&16u16.to_ne_bytes());
    bytes[6..8].copy_from_slice(&5u16.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes[20..24].copy_from_slice(&ifindex.to_ne_bytes());
    bytes[24..28].copy_from_slice(&1u32.to_ne_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_ne_bytes());
    let mut name = name.as_bytes().to_vec();
    name.push(0);
    attr(&mut bytes, 3, &name);
    finish(&mut bytes);
    Ok(bytes)
}

fn owned_tun_identity_fields(actual: &[u8], flags: u16, name: &str, index: u32) -> io::Result<()> {
    ensure(
        name.len() == 11
            && name.starts_with("agv")
            && name.as_bytes()[3..].iter().all(u8::is_ascii_hexdigit)
            && actual == name.as_bytes()
            && flags == 0x1001
            && index > 0
            && index <= i32::MAX as u32,
        "exclusive nonpersistent owned TUN descriptor identity drift",
    )
}
fn recheck_owned_tun_descriptor(tun: &OwnedFd, name: &str, index: u32) -> io::Result<()> {
    let mut identity: libc::ifreq = unsafe { std::mem::zeroed() };
    ensure(
        unsafe { libc::ioctl(tun.as_raw_fd(), 0x800454d2_u64, &mut identity) } == 0,
        "owned TUN descriptor readback refused",
    )?;
    let actual: Vec<u8> = identity
        .ifr_name
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| (*c).to_ne_bytes()[0])
        .collect();
    owned_tun_identity_fields(
        &actual,
        unsafe { identity.ifr_ifru.ifru_flags } as u16,
        name,
        index,
    )?;
    let name = std::ffi::CString::new(name).map_err(|_| refuse("owned TUN name encoding"))?;
    ensure(
        unsafe { libc::if_nametoindex(name.as_ptr()) } == index,
        "owned TUN descriptor/index drift",
    )
}
#[derive(Clone)]
struct OwnedLocalAliasProof {
    original_local_routes: Value,
    physical_addresses: Value,
    original_local_lookup: Value,
    physical_name: String,
    physical_index: u32,
    local: Ipv4Addr,
    own_name: String,
    own_index: u32,
}
fn local_route_row(row: &Value, local: Ipv4Addr, device: &str) -> bool {
    let addr = local.to_string();
    let Some(obj) = row.as_object() else {
        return false;
    };
    obj.keys().all(|key| {
        [
            "type", "dst", "dev", "protocol", "scope", "prefsrc", "flags", "table",
        ]
        .contains(&key.as_str())
    }) && row.get("type").and_then(Value::as_str) == Some("local")
        && row.get("dst").and_then(Value::as_str) == Some(&addr)
        && row.get("dev").and_then(Value::as_str) == Some(device)
        && row.get("protocol").and_then(Value::as_str) == Some("kernel")
        && row.get("scope").and_then(Value::as_str) == Some("host")
        && row.get("prefsrc").and_then(Value::as_str) == Some(&addr)
        && row
            .get("flags")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
        && row
            .get("table")
            .is_none_or(|v| v.as_str() == Some("local") || v.as_u64() == Some(255))
}
fn alias_baseline_eligible(routes: &Value, local: Ipv4Addr, physical: &str) -> io::Result<()> {
    ensure(
        !local.is_unspecified()
            && !local.is_multicast()
            && !local.is_broadcast()
            && !local.is_loopback(),
        "local alias address class",
    )?;
    let rows = routes
        .as_array()
        .ok_or_else(|| refuse("local alias route inventory schema"))?;
    ensure(rows.len() <= 4096, "local alias route inventory bound")?;
    let address = local.to_string();
    let candidates: Vec<_> = rows
        .iter()
        .filter(|row| row.get("dst").and_then(Value::as_str) == Some(&address))
        .collect();
    ensure(
        candidates.len() == 1 && local_route_row(candidates[0], local, physical),
        "physical local alias baseline ambiguous/ineligible",
    )
}
fn alias_routes_after(before: &Value, after: &Value, local: Ipv4Addr, own: &str) -> io::Result<()> {
    let before = before
        .as_array()
        .ok_or_else(|| refuse("local alias baseline schema"))?;
    let after = after
        .as_array()
        .ok_or_else(|| refuse("local alias live schema"))?;
    ensure(
        after.len() == before.len() + 1 && after.len() <= 4096,
        "local alias unexpected route count",
    )?;
    let own_rows: Vec<_> = after
        .iter()
        .filter(|v| v.get("dev").and_then(Value::as_str) == Some(own))
        .collect();
    ensure(
        own_rows.len() == 1 && local_route_row(own_rows[0], local, own),
        "owned local alias missing/drift",
    )?;
    let remaining: Vec<_> = after
        .iter()
        .filter(|v| v.get("dev").and_then(Value::as_str) != Some(own))
        .cloned()
        .collect();
    ensure(
        remaining == *before,
        "foreign or physical local routes changed",
    )
}
fn own_local32_request(index: u32, local: Ipv4Addr, sequence: u32) -> io::Result<Vec<u8>> {
    ensure(
        index > 0 && index <= i32::MAX as u32 && sequence != 0,
        "local alias request identity",
    )?;
    ensure(
        !local.is_unspecified()
            && !local.is_multicast()
            && !local.is_broadcast()
            && !local.is_loopback(),
        "local alias request address class",
    )?;
    let mut bytes = vec![0; 24];
    bytes[4..6].copy_from_slice(&20u16.to_ne_bytes());
    bytes[6..8].copy_from_slice(&0x605u16.to_ne_bytes());
    bytes[8..12].copy_from_slice(&sequence.to_ne_bytes());
    bytes[16] = 2;
    bytes[17] = 32;
    bytes[19] = 254;
    bytes[20..24].copy_from_slice(&index.to_ne_bytes());
    attr(&mut bytes, 1, &local.octets());
    attr(&mut bytes, 2, &local.octets());
    attr(&mut bytes, 8, &0x200u32.to_ne_bytes());
    finish(&mut bytes);
    Ok(bytes)
}
fn alias_address_readback(
    addresses: &Value,
    local: Ipv4Addr,
    name: &str,
    index: u32,
) -> io::Result<()> {
    let rows = addresses
        .as_array()
        .ok_or_else(|| refuse("owned alias address inventory schema"))?;
    ensure(
        rows.len() == 1
            && rows[0].get("ifname").and_then(Value::as_str) == Some(name)
            && rows[0].get("ifindex").and_then(Value::as_u64) == Some(u64::from(index)),
        "owned alias link identity",
    )?;
    let info = rows[0]
        .get("addr_info")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("owned alias addresses absent"))?;
    ensure(
        info.len() == 1,
        "owned alias unexpected address family/count",
    )?;
    let v = &info[0];
    let ip = local.to_string();
    ensure(
        v.get("family").and_then(Value::as_str) == Some("inet")
            && v.get("local").and_then(Value::as_str) == Some(&ip)
            && v.get("prefixlen").and_then(Value::as_u64) == Some(32)
            && v.get("scope").and_then(Value::as_str) == Some("host")
            && v.get("noprefixroute").and_then(Value::as_bool) == Some(true)
            && v.get("label").and_then(Value::as_str) == Some(name)
            && v.get("broadcast").is_none()
            && v.get("peer").is_none()
            && v.get("valid_life_time").and_then(Value::as_u64) == Some(u32::MAX as u64)
            && v.get("preferred_life_time").and_then(Value::as_u64) == Some(u32::MAX as u64),
        "owned local host /32 exact readback",
    )
}
fn alias_physical_link_eligible(links: &Value, name: &str, index: u32) -> io::Result<()> {
    let rows = links
        .as_array()
        .ok_or_else(|| refuse("physical alias link schema"))?;
    ensure(
        rows.len() == 1
            && rows[0].get("ifname").and_then(Value::as_str) == Some(name)
            && rows[0].get("ifindex").and_then(Value::as_u64) == Some(u64::from(index))
            && rows[0].get("master").is_none()
            && rows[0]
                .get("linkinfo")
                .and_then(|v| v.get("info_kind"))
                .and_then(Value::as_str)
                != Some("vrf"),
        "physical alias VRF/master/interface refused",
    )
}
impl OwnedLocalAliasProof {
    fn before(
        request: &RelayOuterGenevaSettings,
        name: &str,
        index: u32,
        physical: u32,
    ) -> io::Result<Self> {
        ensure(index != physical, "alias interface equals physical")?;
        alias_physical_link_eligible(
            &json("ip", &["-j", "link", "show", "dev", &request.interface])?,
            &request.interface,
            physical,
        )?;
        let original_local_routes = json("ip", &["-4", "-j", "route", "show", "table", "local"])?;
        alias_baseline_eligible(
            &original_local_routes,
            request.local_address,
            &request.interface,
        )?;
        let physical_addresses = json("ip", &["-j", "address", "show", "dev", &request.interface])?;
        let original_local_lookup = json(
            "ip",
            &[
                "-4",
                "-j",
                "route",
                "get",
                "fibmatch",
                &request.local_address.to_string(),
            ],
        )?;
        ensure(
            original_local_lookup.as_array().is_some_and(|rows| {
                rows.len() == 1
                    && local_route_row(&rows[0], request.local_address, &request.interface)
            }),
            "physical local lookup not exact first alias",
        )?;
        Ok(Self {
            original_local_routes,
            physical_addresses,
            original_local_lookup,
            physical_name: request.interface.clone(),
            physical_index: physical,
            local: request.local_address,
            own_name: name.into(),
            own_index: index,
        })
    }
    fn verify_physical(&self) -> io::Result<()> {
        alias_physical_link_eligible(
            &json("ip", &["-j", "link", "show", "dev", &self.physical_name])?,
            &self.physical_name,
            self.physical_index,
        )?;
        ensure(
            json("ip", &["-j", "address", "show", "dev", &self.physical_name])?
                == self.physical_addresses,
            "physical addresses changed by owned alias",
        )?;
        ensure(
            json(
                "ip",
                &[
                    "-4",
                    "-j",
                    "route",
                    "get",
                    "fibmatch",
                    &self.local.to_string(),
                ],
            )? == self.original_local_lookup,
            "physical first local lookup changed",
        )
    }
    fn verify_live(&self) -> io::Result<()> {
        self.verify_physical()?;
        alias_address_readback(
            &json("ip", &["-j", "address", "show", "dev", &self.own_name])?,
            self.local,
            &self.own_name,
            self.own_index,
        )?;
        alias_routes_after(
            &self.original_local_routes,
            &json("ip", &["-4", "-j", "route", "show", "table", "local"])?,
            self.local,
            &self.own_name,
        )
    }
    fn verify_removed(&self) -> io::Result<()> {
        self.verify_physical()?;
        ensure(
            json("ip", &["-4", "-j", "route", "show", "table", "local"])?
                == self.original_local_routes,
            "owned local alias removal or physical route restoration unproved",
        )
    }
}

fn configure_owned_link(
    tun: &OwnedFd,
    name: &str,
    request: &RelayOuterGenevaSettings,
    physical: u32,
) -> io::Result<(u32, OwnedLocalAliasProof)> {
    operation_live()?;
    let mut identity: libc::ifreq = unsafe { std::mem::zeroed() };
    ensure(
        unsafe { libc::ioctl(tun.as_raw_fd(), 0x800454d2_u64, &mut identity) } == 0,
        "owned TUN identity refused",
    )?;
    let actual: Vec<_> = identity
        .ifr_name
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| (*c).to_ne_bytes()[0])
        .collect();
    ensure(
        actual == name.as_bytes()
            && (unsafe { identity.ifr_ifru.ifru_flags } as i32 & (1 | 0x1000)) == (1 | 0x1000),
        "owned TUN identity drift",
    )?;
    let own_name = std::ffi::CString::new(name).map_err(|_| refuse("interface name encoding"))?;
    let index = unsafe { libc::if_nametoindex(own_name.as_ptr()) };
    ensure(index > 0, "owned TUN index absent")?;
    let alias = OwnedLocalAliasProof::before(request, name, index, physical)?;
    let all = std::fs::read("/proc/sys/net/ipv4/conf/all/rp_filter")?;
    let all_value = std::str::from_utf8(&all)
        .ok()
        .and_then(|v| v.trim().parse::<u32>().ok())
        .ok_or_else(|| refuse("host reverse path mode schema"))?;
    ensure(all_value <= 2, "host reverse path mode unsupported")?;
    let generation =
        std::path::PathBuf::from(format!("/proc/sys/net/ipv6/conf/{name}/addr_gen_mode"));
    let ipv6 = generation.exists();
    let fd = owned_fd(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    })?;
    let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    address.nl_family = libc::AF_NETLINK as u16;
    ensure(
        unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&address as *const libc::sockaddr_nl).cast(),
                std::mem::size_of_val(&address) as u32,
            )
        } == 0,
        "owned route netlink bind refused",
    )?;
    let port = local_netlink_port(fd.as_raw_fd())?;
    let sequence = rand::thread_rng().next_u32().max(1);
    let configuration = own_link_request(index, name, sequence, ipv6)?;
    own_route_ack(fd.as_raw_fd(), &configuration, port)?;
    ensure(
        unsafe { libc::if_nametoindex(own_name.as_ptr()) } == index
            && std::fs::read("/proc/sys/net/ipv4/conf/all/rp_filter")? == all,
        "TUN/global reverse path binding drift",
    )?;
    ensure(
        std::fs::read(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))? == b"2\n"
            && all_value.max(2) == 2,
        "owned TUN loose reverse path readback",
    )?;
    if ipv6 {
        ensure(
            std::fs::read(generation)? == b"1\n",
            "owned TUN address-generation NONE readback",
        )?;
    }
    let addresses = json("ip", &["-j", "address", "show", "dev", name])?;
    ensure(
        addresses.as_array().is_some_and(|v| {
            v.len() == 1
                && v[0]
                    .get("addr_info")
                    .and_then(Value::as_array)
                    .is_some_and(Vec::is_empty)
        }),
        "owned TUN was not empty before local alias",
    )?;
    // Existing physical address only: no new local destination, broadcast,
    // connected prefix route, or global sysctl mutation. ACK is not route proof.
    recheck_owned_tun_descriptor(tun, name, index)?;
    let address = own_local32_request(
        index,
        request.local_address,
        sequence.wrapping_add(1).max(1),
    )?;
    own_route_ack(fd.as_raw_fd(), &address, port)?;
    let up = own_link_up_request(index, name, sequence.wrapping_add(2).max(1))?;
    own_route_ack(fd.as_raw_fd(), &up, port)?;
    alias.verify_live()?;
    recheck_owned_tun_descriptor(tun, name, index)?;
    ensure(
        unsafe { libc::if_nametoindex(own_name.as_ptr()) } == index
            && std::fs::read("/proc/sys/net/ipv4/conf/all/rp_filter")? == all
            && std::fs::read(format!("/proc/sys/net/ipv4/conf/{name}/rp_filter"))? == b"2\n",
        "owned local alias reverse path/global identity drift",
    )?;
    operation_live()?;
    Ok((index, alias))
}

// NETLINK subscriptions are acquired after exclusive native/table creation, then
// exact canonical baselines are rechecked. Every later NFT mutation must have a
// narrowly expected element+generation receipt while the helper is still unreaped.
struct NetlinkNoticeSocket {
    fd: OwnedFd,
    port: u32,
    groups: u32,
}
struct NoticeDatagram {
    bytes: Vec<u8>,
    group: u32,
}
impl NetlinkNoticeSocket {
    fn open(protocol: i32, groups: u32) -> io::Result<Self> {
        let fd = owned_fd(unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                protocol,
            )
        })?;
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        address.nl_groups = groups;
        ensure(
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    std::mem::size_of_val(&address) as u32,
                )
            } == 0,
            "notification subscription refused",
        )?;
        let mut length = std::mem::size_of_val(&address) as u32;
        ensure(
            unsafe {
                libc::getsockname(
                    fd.as_raw_fd(),
                    (&mut address as *mut libc::sockaddr_nl).cast(),
                    &mut length,
                )
            } == 0
                && length as usize == std::mem::size_of_val(&address)
                && address.nl_family == libc::AF_NETLINK as u16
                && address.nl_groups == groups
                && address.nl_pid != 0,
            "notification port ownership refused",
        )?;
        Ok(Self {
            fd,
            port: address.nl_pid,
            groups,
        })
    }
    fn receive(&self) -> io::Result<Option<NoticeDatagram>> {
        let mut bytes = vec![0u8; 65536];
        let mut sender: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        let mut vector = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        let mut header: libc::msghdr = unsafe { std::mem::zeroed() };
        header.msg_name = (&mut sender as *mut libc::sockaddr_nl).cast();
        header.msg_namelen = std::mem::size_of_val(&sender) as u32;
        header.msg_iov = &mut vector;
        header.msg_iovlen = 1;
        let n = unsafe { libc::recvmsg(self.fd.as_raw_fd(), &mut header, libc::MSG_DONTWAIT) };
        if n < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(e);
        }
        ensure(
            n > 0
                && header.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) == 0
                && header.msg_namelen as usize == std::mem::size_of_val(&sender)
                && sender.nl_family == libc::AF_NETLINK as u16
                && sender.nl_pid == 0
                && sender.nl_groups & !self.groups == 0,
            "notification sender/truncation/loss refused",
        )?;
        bytes.truncate(n as usize);
        Ok(Some(NoticeDatagram {
            bytes,
            group: sender.nl_groups,
        }))
    }
    fn send(&self, bytes: &[u8]) -> io::Result<()> {
        let mut target: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        target.nl_family = libc::AF_NETLINK as u16;
        ensure(
            unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                    (&target as *const libc::sockaddr_nl).cast(),
                    std::mem::size_of_val(&target) as u32,
                )
            } == bytes.len() as isize,
            "notification epoch query send refused",
        )
    }
}
#[derive(Debug)]
struct NoticeMessage<'a> {
    kind: u16,
    flags: u16,
    sequence: u32,
    port: u32,
    body: &'a [u8],
}
fn notice_messages(bytes: &[u8]) -> io::Result<Vec<NoticeMessage<'_>>> {
    ensure(
        !bytes.is_empty() && bytes.len() <= 65536,
        "notification datagram resource bound",
    )?;
    let mut rows = Vec::new();
    let mut offset = 0;
    while offset < bytes.len() {
        ensure(
            rows.len() < 64 && bytes.len() - offset >= 16,
            "notification header/count refused",
        )?;
        let h = &bytes[offset..];
        let length = u32::from_ne_bytes(h[..4].try_into().unwrap()) as usize;
        ensure(
            length >= 16 && length <= h.len(),
            "notification message length refused",
        )?;
        rows.push(NoticeMessage {
            kind: u16::from_ne_bytes(h[4..6].try_into().unwrap()),
            flags: u16::from_ne_bytes(h[6..8].try_into().unwrap()),
            sequence: u32::from_ne_bytes(h[8..12].try_into().unwrap()),
            port: u32::from_ne_bytes(h[12..16].try_into().unwrap()),
            body: &h[16..length],
        });
        let aligned = (length + 3) & !3;
        if length == h.len() {
            offset = bytes.len()
        } else {
            ensure(
                aligned <= h.len() && h[length..aligned].iter().all(|v| *v == 0),
                "notification message padding refused",
            )?;
            offset += aligned;
        }
    }
    Ok(rows)
}
// Failure-only metadata: never retain route attributes or raw datagram bodies.
// The normal group/neighbor/refresh acceptance remains unchanged.
fn route_origin_refusal_metadata(data: &NoticeDatagram, pinned_ifindex: u32) -> Option<Value> {
    if data.group == 4 {
        return None;
    }
    let within_bound = data.bytes.len() <= 65536;
    let mut headers = Vec::new();
    let mut complete = false;
    if let Ok(rows) = notice_messages(&data.bytes) {
        for row in rows {
            // ifinfomsg/ndmsg place their signed interface index at offset 4.
            // This is an untrusted diagnostic candidate, never an ownership proof.
            let candidate = if matches!(row.kind, 16 | 17 | 28 | 29) && row.body.len() >= 8 {
                Some(i32::from_ne_bytes(row.body[4..8].try_into().unwrap()))
            } else {
                None
            };
            headers.push(serde_json::json!({
                "type":row.kind,"flags":row.flags,"sequence":row.sequence,
                "port_id":row.port,"message_length":row.body.len()+16,
                "candidate_ifindex":candidate
            }));
        }
        complete = true;
    }
    Some(serde_json::json!({
        "schema":"aegis_route_notification_refusal_metadata_v1",
        "group_mask":data.group,"subscribed_group_mask":1|4|16|64|128,
        "required_group_mask":4,"pinned_ifindex":pinned_ifindex,
        "datagram_length":data.bytes.len(),
        "datagram_sha256":within_bound.then(||hex::encode(sha2::Sha256::digest(&data.bytes))),
        "headers":headers,"headers_complete":complete,
        "datagram_within_bound":within_bound,"raw_body_retained":false,
        "origin_accepted":false,"candidate_interface_ownership_proven":false
    }))
}

fn notice_attrs(bytes: &[u8]) -> io::Result<BTreeMap<u16, &[u8]>> {
    let mut rows = BTreeMap::new();
    let mut offset = 0;
    while offset < bytes.len() {
        ensure(
            rows.len() < 32 && bytes.len() - offset >= 4,
            "notification attribute count/header refused",
        )?;
        let h = &bytes[offset..];
        let length = u16::from_ne_bytes(h[..2].try_into().unwrap()) as usize;
        let kind = u16::from_ne_bytes(h[2..4].try_into().unwrap());
        ensure(
            length >= 4 && length <= h.len() && kind & 0x4000 == 0,
            "notification attribute length/flags refused",
        )?;
        ensure(
            rows.insert(kind & 0x3fff, &h[4..length]).is_none(),
            "duplicate notification attribute refused",
        )?;
        let aligned = (length + 3) & !3;
        if length == h.len() {
            offset = bytes.len()
        } else {
            ensure(
                aligned <= h.len() && h[length..aligned].iter().all(|v| *v == 0),
                "notification attribute padding refused",
            )?;
            offset += aligned;
        }
    }
    Ok(rows)
}
fn notice_string(bytes: &[u8]) -> io::Result<&str> {
    ensure(
        !bytes.is_empty()
            && bytes.len() <= 256
            && bytes.last() == Some(&0)
            && !bytes[..bytes.len() - 1].contains(&0),
        "notification string refused",
    )?;
    std::str::from_utf8(&bytes[..bytes.len() - 1]).map_err(|_| refuse("notification text refused"))
}
struct NftGeneration {
    generation: u32,
    pid: u32,
    name: String,
}
fn notice_generation(row: &NoticeMessage<'_>) -> io::Result<NftGeneration> {
    ensure(
        row.kind == 0x0a0f && row.flags == 0 && row.body.len() >= 4 && row.body[..2] == [0, 0],
        "NFT generation header refused",
    )?;
    let attrs = notice_attrs(&row.body[4..])?;
    ensure(attrs.len() == 3, "NFT generation schema refused")?;
    let generation = attrs
        .get(&1)
        .filter(|v| v.len() == 4)
        .map(|v| u32::from_be_bytes((*v).try_into().unwrap()))
        .ok_or_else(|| refuse("NFT generation missing"))?;
    let pid = attrs
        .get(&2)
        .filter(|v| v.len() == 4)
        .map(|v| u32::from_be_bytes((*v).try_into().unwrap()))
        .ok_or_else(|| refuse("NFT actor PID missing"))?;
    ensure(
        u16::from_be_bytes(row.body[2..4].try_into().unwrap()) == generation as u16,
        "NFT low epoch mismatch",
    )?;
    let name = notice_string(
        attrs
            .get(&3)
            .ok_or_else(|| refuse("NFT actor name missing"))?,
    )?
    .to_owned();
    ensure(pid > 0 && name.len() <= 15, "NFT actor shape refused")?;
    Ok(NftGeneration {
        generation,
        pid,
        name,
    })
}
fn next_nft_generation(previous: u32) -> u32 {
    previous.wrapping_add(1).max(1)
}
fn notice_tuple(
    row: &NoticeMessage<'_>,
    table: &str,
    pin: RelayFlowPin,
    add: bool,
    generation: u32,
) -> io::Result<()> {
    ensure(
        row.kind == if add { 0x0a0c } else { 0x0a0e }
            && row.flags & !0x600 == 0
            && row.sequence == 0
            && row.port > 0
            && row.body.len() >= 4
            && row.body[..2] == [2, 0]
            && u16::from_be_bytes(row.body[2..4].try_into().unwrap()) == generation as u16,
        "NFT element header/epoch refused",
    )?;
    let attrs = notice_attrs(&row.body[4..])?;
    ensure(attrs.len() == 3, "NFT element schema refused")?;
    ensure(
        notice_string(attrs.get(&1).ok_or_else(|| refuse("NFT table absent"))?)? == table
            && notice_string(attrs.get(&2).ok_or_else(|| refuse("NFT set absent"))?)? == "flows",
        "NFT element ownership refused",
    )?;
    let list = notice_attrs(
        attrs
            .get(&3)
            .ok_or_else(|| refuse("NFT element list absent"))?,
    )?;
    ensure(list.len() == 1, "NFT element list refused")?;
    let element = notice_attrs(
        list.get(&1)
            .ok_or_else(|| refuse("NFT single element absent"))?,
    )?;
    ensure(element.len() == 1, "NFT extra element field refused")?;
    let key = notice_attrs(element.get(&1).ok_or_else(|| refuse("NFT key absent"))?)?;
    ensure(key.len() == 1, "NFT extra key field refused")?;
    let raw = *key.get(&1).ok_or_else(|| refuse("NFT raw key absent"))?;
    let mut expected = Vec::with_capacity(16);
    expected.extend(pin.relay.octets());
    expected.extend(pin.relay_port.to_be_bytes());
    expected.extend([0, 0]);
    expected.extend(pin.local.octets());
    expected.extend(pin.local_port.to_be_bytes());
    expected.extend([0, 0]);
    ensure(raw == expected, "NFT changed tuple refused")
}
fn admissible_neighbor(
    row: &NoticeMessage<'_>,
    request: &RelayOuterGenevaSettings,
    index: u32,
    routes: &[RouteProof],
) -> io::Result<()> {
    ensure(
        row.kind == 28
            && row.flags == 0
            && row.sequence == 0
            && row.port == 0
            && row.body.len() >= 12
            && row.body[0] == 2
            && row.body[1..4] == [0, 0, 0]
            && u32::from_ne_bytes(row.body[4..8].try_into().unwrap()) == index
            && [2, 4, 8, 16, 128]
                .contains(&u16::from_ne_bytes(row.body[8..10].try_into().unwrap()))
            && [0, 128].contains(&row.body[10])
            && row.body[11] == 1,
        "route event not an admissible pinned neighbor transition",
    )?;
    let attrs = notice_attrs(&row.body[12..])?;
    for (kind, bytes) in &attrs {
        ensure(
            match *kind {
                1 => bytes.len() == 4,
                2 => bytes.len() == 6,
                3 => bytes.len() == 16,
                4 => bytes.len() == 4,
                _ => false,
            },
            "neighbor extra metadata refused",
        )?;
    }
    let target = attrs
        .get(&1)
        .filter(|v| v.len() == 4)
        .map(|v| Ipv4Addr::from(<[u8; 4]>::try_from(*v).unwrap()))
        .ok_or_else(|| refuse("neighbor address absent"))?;
    ensure(
        routes.iter().any(|r| r.via == target)
            && attrs.get(&2).is_some_and(|v| *v == request.next_hop_mac),
        "neighbor pinned destination/MAC drift",
    )
}
struct OwnedNftExpectation<'a> {
    generation: u32,
    pid: u32,
    name: &'a str,
    table: &'a str,
    pin: RelayFlowPin,
    add: bool,
    element_port: Option<u32>,
    complete: bool,
}
impl OwnedNftExpectation<'_> {
    fn consume(&mut self, bytes: &[u8]) -> io::Result<()> {
        ensure(!self.complete, "duplicate completed NFT transaction")?;
        let rows = notice_messages(bytes)?;
        for (position, row) in rows.iter().enumerate() {
            if row.kind == 0x0a0f {
                ensure(
                    position + 1 == rows.len(),
                    "extra NFT event after generation refused",
                )?;
                let receipt = notice_generation(row)?;
                ensure(
                    self.element_port == Some(row.port)
                        && receipt.generation == self.generation
                        && receipt.pid == self.pid
                        && receipt.name == self.name,
                    "NFT generation not exact unreaped owned helper",
                )?;
                self.complete = true;
            } else {
                ensure(
                    self.element_port.is_none(),
                    "duplicate/unexpected NFT mutation event",
                )?;
                notice_tuple(row, self.table, self.pin, self.add, self.generation)?;
                self.element_port = Some(row.port);
            }
        }
        Ok(())
    }
}

struct NotificationWatch {
    nft: NetlinkNoticeSocket,
    route: NetlinkNoticeSocket,
    generation: u32,
    route_epoch: u64,
    route_events: u64,
}
impl NotificationWatch {
    fn new() -> io::Result<Self> {
        let nft = NetlinkNoticeSocket::open(12, 64)?;
        let route = NetlinkNoticeSocket::open(0, 1 | 4 | 16 | 64 | 128)?;
        let sequence = rand::thread_rng().next_u32().max(1);
        let mut request = message(0x0a10, 0, sequence);
        request[6..8].copy_from_slice(&1u16.to_ne_bytes());
        request[16] = 0;
        finish(&mut request);
        nft.send(&request)?;
        let deadline = finite_deadline(Duration::from_millis(500));
        let generation = loop {
            ensure(Instant::now() < deadline, "NFT epoch baseline deadline")?;
            if let Some(data) = nft.receive()? {
                let rows = notice_messages(&data.bytes)?;
                ensure(
                    data.group == 0
                        && rows.len() == 1
                        && rows[0].sequence == sequence
                        && rows[0].port == nft.port,
                    "NFT epoch baseline mixed with mutation",
                )?;
                break notice_generation(&rows[0])?.generation;
            }
            thread::sleep(Duration::from_millis(2));
        };
        Ok(Self {
            nft,
            route,
            generation,
            route_epoch: 0,
            route_events: 0,
        })
    }
    fn no_nft_change(&self) -> io::Result<()> {
        if let Some(data) = self.nft.receive()? {
            return Err(refuse(&format!(
                "unaccounted NFT mutation/event refused; group={} sha256={}",
                data.group,
                hex::encode(sha2::Sha256::digest(&data.bytes))
            )));
        }
        Ok(())
    }
    fn route_events(
        &mut self,
        request: &RelayOuterGenevaSettings,
        index: u32,
        routes: &[RouteProof],
        journal: &Journal,
    ) -> io::Result<Vec<String>> {
        let mut hashes = BTreeSet::new();
        for _ in 0..32 {
            let Some(data) = self.route.receive()? else {
                return Ok(hashes.into_iter().collect());
            };
            if let Some(metadata) = route_origin_refusal_metadata(&data, index) {
                // Retention failure must never turn the original refusal into success.
                let _ = journal.record("route_notification_refused", metadata);
                return Err(refuse("route multicast origin refused"));
            }
            let digest = hex::encode(sha2::Sha256::digest(&data.bytes));
            ensure(
                hashes.insert(digest),
                "duplicate route event datagram refused",
            )?;
            for row in notice_messages(&data.bytes)? {
                admissible_neighbor(&row, request, index, routes)?;
                self.route_events = self
                    .route_events
                    .checked_add(1)
                    .ok_or_else(|| refuse("route event count overflow"))?;
                ensure(self.route_events <= 4096, "route event lifetime quota")?;
            }
        }
        Err(refuse("route event drain bound/loss refused"))
    }
    fn own_element(
        &mut self,
        pid: u32,
        name: &str,
        table: &str,
        pin: RelayFlowPin,
        add: bool,
        journal: &Journal,
    ) -> io::Result<()> {
        let mut expected = OwnedNftExpectation {
            generation: next_nft_generation(self.generation),
            pid,
            name,
            table,
            pin,
            add,
            element_port: None,
            complete: false,
        };
        let deadline = finite_deadline(Duration::from_millis(500));
        let mut hashes = Vec::new();
        loop {
            operation_live()?;
            ensure(Instant::now() < deadline, "owned NFT notification deadline")?;
            if let Some(data) = self.nft.receive()? {
                ensure(
                    data.group == 64 && hashes.len() < 4,
                    "owned NFT multicast/batch bound refused",
                )?;
                hashes.push(hex::encode(sha2::Sha256::digest(&data.bytes)));
                expected.consume(&data.bytes)?;
                if expected.complete {
                    self.generation = expected.generation;
                    self.no_nft_change()?;
                    return journal.record(if add{"owned_nft_epoch"}else{"owned_nft_delete_epoch"},serde_json::json!({"generation":expected.generation,"unreaped_helper_pid":pid,"helper_name":name,"table":table,"tuple":pin_json(pin),"add":add,"event_sha256":hashes,"no_own_events_ignored":true}));
                }
            } else {
                thread::sleep(Duration::from_millis(2))
            }
        }
    }
}

struct NativeQueue {
    fd: OwnedFd,
    number: u16,
    port_id: u32,
    next_sequence: u32,
    pending: VecDeque<Vec<u8>>,
}
impl NativeQueue {
    fn bind(number: u16) -> io::Result<Self> {
        let fd = owned_fd(unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                12,
            )
        })?;
        let mut address: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        address.nl_family = libc::AF_NETLINK as u16;
        ensure(
            unsafe {
                libc::bind(
                    fd.as_raw_fd(),
                    (&address as *const libc::sockaddr_nl).cast(),
                    std::mem::size_of_val(&address) as u32,
                )
            } == 0,
            "NFQUEUE bind refused",
        )?;
        let port_id = local_netlink_port(fd.as_raw_fd())?;
        let mut q = Self {
            fd,
            number,
            port_id,
            next_sequence: 1,
            pending: VecDeque::new(),
        };
        let mut command = message(0x302, number, q.next_sequence);
        attr(&mut command, 1, &[1, 0, 0, 2]);
        q.exchange(command, false)?;
        let mut options = message(0x302, number, q.next_sequence);
        attr(&mut options, 2, &[0, 0, 255, 255, 2]);
        attr(&mut options, 3, &(QUEUE_LIMIT as u32).to_be_bytes());
        // All known NFQA flags disabled: FAIL_OPEN, CONNTRACK, GSO, UID_GID, SECCTX.
        attr(&mut options, 4, &31u32.to_be_bytes());
        attr(&mut options, 5, &0u32.to_be_bytes());
        q.exchange(options, false)?;
        Ok(q)
    }
    fn exchange(&mut self, mut bytes: Vec<u8>, packets_allowed: bool) -> io::Result<()> {
        let sequence = self.next_sequence;
        ensure(
            bytes.get(8..12) == Some(sequence.to_ne_bytes().as_slice()),
            "netlink request sequence drift",
        )?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| refuse("netlink sequence exhausted"))?;
        finish(&mut bytes);
        let mut kernel: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        kernel.nl_family = libc::AF_NETLINK as u16;
        ensure(
            unsafe {
                libc::sendto(
                    self.fd.as_raw_fd(),
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                    (&kernel as *const libc::sockaddr_nl).cast(),
                    std::mem::size_of_val(&kernel) as u32,
                )
            } == bytes.len() as isize,
            "netlink request failed",
        )?;
        operation_live()?;
        let deadline = finite_deadline(Duration::from_millis(500));
        loop {
            ensure(Instant::now() < deadline, "netlink ACK deadline")?;
            let Some(reply) = receive(self.fd.as_raw_fd(), Duration::from_millis(10))? else {
                continue;
            };
            ensure(reply.len() >= 20, "netlink reply truncated")?;
            let kind = u16::from_ne_bytes(reply[4..6].try_into().unwrap());
            if kind == 2 {
                ensure(
                    exact_success_ack(&reply, &bytes, self.port_id),
                    "netlink ACK/refusal",
                )?;
                return Ok(());
            }
            ensure(
                packets_allowed && kind == 0x300 && self.pending.len() < QUEUE_LIMIT,
                "unexpected netlink reply/budget",
            )?;
            self.pending.push_back(reply);
        }
    }
    fn drop_original(&mut self, id: u32) -> io::Result<()> {
        let mut bytes = message(0x301, self.number, self.next_sequence);
        let mut verdict = vec![0; 4];
        verdict.extend_from_slice(&id.to_be_bytes());
        attr(&mut bytes, 2, &verdict);
        self.exchange(bytes, true)
    }
    fn packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        if let Some(v) = self.pending.pop_front() {
            Ok(Some(v))
        } else {
            receive(self.fd.as_raw_fd(), Duration::from_millis(1))
        }
    }
}
struct NativeIo {
    outbound: NativeQueue,
    inbound: NativeQueue,
    ethernet: OwnedFd,
    tun: OwnedFd,
    ifindex: u32,
    tun_ifindex: u32,
    local_alias: OwnedLocalAliasProof,
}
impl NativeIo {
    fn new(request: &RelayOuterGenevaSettings, ifindex: u32, token: &str) -> io::Result<Self> {
        operation_live()?;
        operation_live()?;
        let outbound = NativeQueue::bind(request.outbound_queue)?;
        operation_live()?;
        let inbound = NativeQueue::bind(request.inbound_queue)?;
        let ethernet = owned_fd(unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        })?;
        option(ethernet.as_raw_fd(), libc::SO_MARK, &request.socket_mark)?;
        let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
        addr.sll_family = libc::AF_PACKET as u16;
        addr.sll_protocol = 0;
        addr.sll_ifindex = ifindex as i32;
        ensure(
            unsafe {
                libc::bind(
                    ethernet.as_raw_fd(),
                    (&addr as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&addr) as u32,
                )
            } == 0,
            "AF_PACKET bind refused",
        )?;
        operation_live()?;
        let tun = owned_fd(unsafe {
            libc::open(
                c"/dev/net/tun".as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK | libc::O_NOFOLLOW,
            )
        })?;
        let tun_name = format!("agv{token}");
        let mut ifr: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in ifr.ifr_name.iter_mut().zip(tun_name.bytes()) {
            *dst = src as libc::c_char;
        }
        ifr.ifr_ifru.ifru_flags = (1 | 0x1000 | 0x8000) as i16;
        ensure(
            unsafe { libc::ioctl(tun.as_raw_fd(), 0x400454ca_u64, &mut ifr) } == 0,
            "exclusive nonpersistent TUN refused",
        )?;
        let zero = 0i32;
        ensure(
            unsafe { libc::ioctl(tun.as_raw_fd(), 0x400454d0_u64, zero) } == 0,
            "TUN offload disable refused",
        )?;
        let (tun_ifindex, local_alias) = configure_owned_link(&tun, &tun_name, request, ifindex)?;
        Ok(Self {
            outbound,
            inbound,
            ethernet,
            tun,
            ifindex,
            tun_ifindex,
            local_alias,
        })
    }
    fn emit(&self, frame: &[u8], outbound: bool) -> io::Result<()> {
        let bytes = if outbound {
            frame
        } else {
            frame
                .get(14..)
                .ok_or_else(|| refuse("inbound frame boundary"))?
        };
        let fd = if outbound {
            self.ethernet.as_raw_fd()
        } else {
            self.tun.as_raw_fd()
        };
        let count = if outbound {
            let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            address.sll_family = libc::AF_PACKET as u16;
            address.sll_protocol = 0x0800u16.to_be();
            address.sll_ifindex = self.ifindex as i32;
            unsafe {
                libc::sendto(
                    fd,
                    bytes.as_ptr().cast(),
                    bytes.len(),
                    libc::MSG_DONTWAIT,
                    (&address as *const libc::sockaddr_ll).cast(),
                    std::mem::size_of_val(&address) as u32,
                )
            }
        } else {
            unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) }
        };
        ensure(
            count == bytes.len() as isize,
            "ordered packet reinjection refused",
        )
    }
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(pair[0]) << 8 | u32::from(*pair.get(1).unwrap_or(&0));
    }
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !(sum as u16)
}
fn ethernet_packet(
    payload: &[u8],
    pending: bool,
    request: &RelayOuterGenevaSettings,
    outbound: bool,
) -> io::Result<Vec<u8>> {
    ensure(
        payload.len() >= 40 && payload[0] >> 4 == 4 && payload[9] == 6,
        "original is not full IPv4 TCP",
    )?;
    let ihl = usize::from(payload[0] & 15) * 4;
    ensure(
        ihl >= 20
            && ihl + 20 <= payload.len()
            && u16::from_be_bytes([payload[2], payload[3]]) as usize == payload.len()
            && u16::from_be_bytes([payload[6], payload[7]]) & 0x3fff == 0,
        "original IPv4 layout/fragment refused",
    )?;
    let tcp_len = payload.len() - ihl;
    let dataoff = usize::from(payload[ihl + 12] >> 4) * 4;
    ensure(
        (20..=tcp_len).contains(&dataoff) && checksum(&payload[..ihl]) == 0,
        "original headers refused",
    )?;
    let mut ip = payload.to_vec();
    if pending {
        ensure(outbound, "inbound incomplete checksum refused")?;
        ip[ihl + 16..ihl + 18].fill(0);
    }
    let mut pseudo = ip[12..20].to_vec();
    pseudo.extend([0, 6]);
    pseudo.extend((tcp_len as u16).to_be_bytes());
    pseudo.extend(&ip[ihl..]);
    if pending {
        let sum = checksum(&pseudo);
        ip[ihl + 16..ihl + 18].copy_from_slice(&sum.to_be_bytes());
    } else {
        ensure(checksum(&pseudo) == 0, "original TCP checksum invalid")?;
    }
    let mut frame = Vec::with_capacity(ip.len() + 14);
    frame.extend(if outbound {
        request.next_hop_mac
    } else {
        request.local_mac
    });
    frame.extend(if outbound {
        request.local_mac
    } else {
        request.next_hop_mac
    });
    frame.extend([8, 0]);
    frame.extend(ip);
    Ok(frame)
}

fn has_mark(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            map.get("meta")
                .and_then(|v| v.get("key"))
                .and_then(Value::as_str)
                == Some("mark")
                || map.values().any(has_mark)
        }
        Value::Array(rows) => rows.iter().any(has_mark),
        _ => false,
    }
}
fn mark_literal(value: &Value) -> io::Result<u32> {
    if let Some(n) = value.as_u64() {
        return u32::try_from(n).map_err(|_| refuse("mark literal width refused"));
    }
    if let Some(text) = value.as_str() {
        if let Some(hex) = text.strip_prefix("0x") {
            ensure(
                !hex.is_empty() && hex.len() <= 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()),
                "mark hex literal refused",
            )?;
            return u32::from_str_radix(hex, 16).map_err(|_| refuse("mark hex width refused"));
        }
    }
    Err(refuse("unsupported mark literal"))
}
fn selected_mark_value(value: &Value, selected: u32) -> io::Result<u32> {
    if value
        .get("meta")
        .and_then(|v| v.get("key"))
        .and_then(Value::as_str)
        == Some("mark")
    {
        ensure(
            value.as_object().is_some_and(|m| m.len() == 1),
            "mark expression extra fields",
        )?;
        return Ok(selected);
    }
    if let Some(terms) = value.get("&").and_then(Value::as_array) {
        ensure(
            terms.len() == 2 && value.as_object().is_some_and(|m| m.len() == 1),
            "mark mask shape refused",
        )?;
        return Ok(selected_mark_value(&terms[0], selected)? & mark_literal(&terms[1])?);
    }
    Err(refuse("unsupported mark expression"))
}
fn validate_mark_reservation(rules: &Value, table: &str, selected: u32) -> io::Result<()> {
    let objects = rules
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("prearm nft schema refused"))?;
    for object in objects {
        if object
            .get("table")
            .and_then(|v| v.get("name"))
            .and_then(Value::as_str)
            == Some(table)
        {
            return Err(refuse("exclusive table already present"));
        }
        let Some(rule) = object.get("rule") else {
            continue;
        };
        let expressions = rule
            .get("expr")
            .and_then(Value::as_array)
            .ok_or_else(|| refuse("prearm rule expression schema"))?;
        for expression in expressions {
            if !has_mark(expression) {
                continue;
            }
            // Dynamic setters and other mark consumers are not silently assumed disjoint.
            let matched = expression
                .get("match")
                .ok_or_else(|| refuse("existing dynamic mark policy unsupported"))?;
            ensure(
                matched.as_object().is_some_and(|m| m.len() == 3),
                "mark match shape refused",
            )?;
            let left = matched
                .get("left")
                .ok_or_else(|| refuse("mark left absent"))?;
            let right = mark_literal(
                matched
                    .get("right")
                    .ok_or_else(|| refuse("mark right absent"))?,
            )?;
            let value = selected_mark_value(left, selected)?;
            let selects = match matched.get("op").and_then(Value::as_str) {
                Some("==") => value == right,
                Some("!=") => value != right,
                _ => return Err(refuse("existing mark comparison unsupported")),
            };
            ensure(!selects, "selected mark intersects existing policy")?;
        }
    }
    Ok(())
}
// Select a complete table from one numeric ruleset observation, never a prefix.
fn table_snapshot(rules: &Value, family: &str, table: &str) -> io::Result<Value> {
    let rows = rules
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("ruleset table selection schema refused"))?;
    let mut selected = Vec::new();
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| refuse("ruleset object schema refused"))?;
        ensure(object.len() == 1, "ruleset object ambiguity refused")?;
        let (kind, body) = object
            .iter()
            .next()
            .ok_or_else(|| refuse("empty ruleset object"))?;
        if kind == "metainfo" {
            continue;
        }
        let body = body
            .as_object()
            .ok_or_else(|| refuse("ruleset body schema refused"))?;
        let name = if kind == "table" {
            body.get("name")
        } else {
            body.get("table")
        };
        if body.get("family").and_then(Value::as_str) == Some(family)
            && name.and_then(Value::as_str) == Some(table)
        {
            selected.push(row.clone());
        }
    }
    ensure(!selected.is_empty(), "selected complete table absent")?;
    Ok(serde_json::json!({"nftables":selected}))
}
fn without_verified_tables(rules: &Value, verified: &[(&str, &str)]) -> io::Result<Value> {
    let rows = rules
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(|| refuse("ruleset filtering schema refused"))?;
    let mut kept = Vec::new();
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| refuse("ruleset object schema refused"))?;
        ensure(object.len() == 1, "ruleset object ambiguity refused")?;
        let (kind, body) = object
            .iter()
            .next()
            .ok_or_else(|| refuse("empty ruleset object"))?;
        let family = body.get("family").and_then(Value::as_str);
        let name = body
            .get(if kind == "table" { "name" } else { "table" })
            .and_then(Value::as_str);
        if !verified
            .iter()
            .any(|(f, t)| family == Some(*f) && name == Some(*t))
        {
            kept.push(row.clone());
        }
    }
    Ok(serde_json::json!({"nftables":kept}))
}
fn validate_installed_proof(
    proof: &InstalledGuardProof,
    snapshot: &Value,
    source: &str,
    request: &RelayOuterGenevaSettings,
) -> io::Result<()> {
    ensure(
        proof.table_family() == "netdev"
            && proof.table_name() == installed_guard::TABLE
            && proof.source_commit() == source
            && proof.interface() == request.interface
            && proof.socket_mark() == request.socket_mark
            && proof.table_sha256() == installed_guard::canonical_table_digest(snapshot)?,
        "installed authorization differs from same ruleset snapshot",
    )
}
fn registration_pin_available(
    pin: RelayFlowPin,
    active: impl Iterator<Item = RelayFlowPin>,
    retired: &[RelayFlowPin],
) -> bool {
    !retired.contains(&pin) && !active.into_iter().any(|existing| existing == pin)
}

fn validate_owned_elements(
    observed: &[RelayFlowPin],
    intents: &[(RelayFlowPin, Option<bool>)],
) -> io::Result<()> {
    ensure(
        observed
            .iter()
            .all(|pin| intents.iter().any(|(owned, _)| owned == pin)),
        "unowned nft tuple observed",
    )?;
    for (pin, presence) in intents {
        if let Some(expected) = presence {
            ensure(
                observed.contains(pin) == *expected,
                "recorded tuple presence drift",
            )?;
        }
    }
    Ok(())
}
fn frame_pin(frame: &[u8], outbound: bool) -> io::Result<RelayFlowPin> {
    ensure(
        frame.len() >= 54 && frame[12..14] == [8, 0] && frame[23] == 6,
        "tuple frame layout",
    )?;
    let at = 14 + usize::from(frame[14] & 15) * 4;
    let ports = frame
        .get(at..at + 4)
        .ok_or_else(|| refuse("tuple ports absent"))?;
    let src =
        Ipv4Addr::from(<[u8; 4]>::try_from(&frame[26..30]).map_err(|_| refuse("tuple source"))?);
    let dst = Ipv4Addr::from(
        <[u8; 4]>::try_from(&frame[30..34]).map_err(|_| refuse("tuple destination"))?,
    );
    let sport = u16::from_be_bytes([ports[0], ports[1]]);
    let dport = u16::from_be_bytes([ports[2], ports[3]]);
    Ok(if outbound {
        RelayFlowPin {
            local: src,
            relay: dst,
            local_port: sport,
            relay_port: dport,
        }
    } else {
        RelayFlowPin {
            local: dst,
            relay: src,
            local_port: dport,
            relay_port: sport,
        }
    })
}
struct Flow {
    pin: RelayFlowPin,
    program: RelayGenevaProgram,
    duplicate: Option<Arc<OwnedFd>>,
    inode: u64,
    route: RouteProof,
    retiring: bool,
    presence: Option<bool>,
}
struct State {
    flows: BTreeMap<u64, Flow>,
    retired: Vec<RelayFlowPin>,
    next_token: u64,
    table_present: bool,
    quiesced: bool,
}

fn self_process_identity() -> io::Result<Value> {
    use std::os::unix::fs::MetadataExt;
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    ensure(stat.len() <= 8192, "process identity bound")?;
    let tail = stat
        .rsplit_once(')')
        .ok_or_else(|| refuse("process stat schema"))?
        .1;
    let ticks = tail
        .split_whitespace()
        .nth(19)
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| refuse("process start ticks absent"))?;
    let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
    ensure(
        boot.len() == 37
            && boot
                .trim()
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b'-'),
        "boot identity schema",
    )?;
    let namespace = std::fs::metadata("/proc/self/ns/net")?;
    let invocation = std::env::var("INVOCATION_ID").ok();
    if let Some(value) = &invocation {
        ensure(
            value.len() == 32 && value.bytes().all(|b| b.is_ascii_hexdigit()),
            "service invocation identity malformed",
        )?;
    }
    let cgroup = std::fs::read_to_string("/proc/self/cgroup")?;
    ensure(
        cgroup.len() <= 8192 && cgroup.lines().count() == 1 && cgroup.starts_with("0::/"),
        "native unified cgroup identity refused",
    )?;
    Ok(
        serde_json::json!({"boot_id":boot.trim(),"pid":unsafe{libc::getpid()},"start_ticks":ticks,"network_namespace_inode":namespace.ino(),"network_namespace_device":namespace.dev(),"service_invocation_id":invocation,"unified_cgroup":cgroup.trim(),"service_profile_measured":false}),
    )
}
fn pin_json(pin: RelayFlowPin) -> Value {
    serde_json::json!({"local":pin.local,"relay":pin.relay,"local_port":pin.local_port,"relay_port":pin.relay_port})
}

struct Journal {
    root: std::path::PathBuf,
    inode: u64,
    device: u64,
    next: AtomicU64,
    normal_records: AtomicU64,
    terminal_records: AtomicU64,
    cleanup_records: AtomicU64,
    cleanup_bytes: AtomicU64,
    normal_bytes: AtomicU64,
    terminal_bytes: AtomicU64,
}
impl Journal {
    fn new(token: &str) -> io::Result<Self> {
        use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
        let parent = std::path::Path::new("/run/aegis-relay-geneva");
        match std::fs::DirBuilder::new().mode(0o700).create(parent) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
        let metadata = std::fs::symlink_metadata(parent)?;
        ensure(
            metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.uid() == 0
                && metadata.permissions().mode() & 0o777 == 0o700,
            "native evidence parent not exclusively owned",
        )?;
        let root = parent.join(token);
        std::fs::DirBuilder::new().mode(0o700).create(&root)?;
        let own = std::fs::symlink_metadata(&root)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(Self {
            root,
            inode: own.ino(),
            device: own.dev(),
            next: AtomicU64::new(0),
            normal_records: AtomicU64::new(0),
            terminal_records: AtomicU64::new(0),
            cleanup_records: AtomicU64::new(0),
            cleanup_bytes: AtomicU64::new(0),
            normal_bytes: AtomicU64::new(0),
            terminal_bytes: AtomicU64::new(0),
        })
    }
    fn record(&self, phase: &str, value: Value) -> io::Result<()> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
        let owned = std::fs::symlink_metadata(&self.root)?;
        ensure(
            owned.is_dir()
                && !owned.file_type().is_symlink()
                && owned.uid() == 0
                && owned.permissions().mode() & 0o777 == 0o700
                && owned.ino() == self.inode
                && owned.dev() == self.device,
            "native journal ownership drift",
        )?;
        ensure(
            phase
                .bytes()
                .all(|v| v.is_ascii_alphanumeric() || v == b'_'),
            "journal phase refused",
        )?;
        let data =
            serde_json::to_vec(&value).map_err(|_| refuse("journal serialization refused"))?;
        ensure(data.len() <= 65536, "journal resource bound")?;
        let terminal = [
            "fail_closed",
            "runtime_fault",
            "worker_terminal",
            "worker_failed",
            "quiesced",
            "setup_failed",
            "readiness_failed",
        ]
        .contains(&phase);
        let (records, bytes, max_records, max_bytes) = if terminal {
            (&self.terminal_records, &self.terminal_bytes, 8, 1048576)
        } else if [
            "flow_retire_intent",
            "flow_delete_intent",
            "flow_retired",
            "linger_failed",
            "owned_nft_delete_epoch",
        ]
        .contains(&phase)
        {
            (
                &self.cleanup_records,
                &self.cleanup_bytes,
                4096,
                2 * 1048576,
            )
        } else {
            (&self.normal_records, &self.normal_bytes, 4096, 15 * 1048576)
        };
        ensure(
            records.fetch_add(1, Ordering::AcqRel) < max_records
                && bytes.fetch_add(data.len() as u64, Ordering::AcqRel) + data.len() as u64
                    <= max_bytes,
            "journal total quota exhausted; terminal reserve protected",
        )?;
        let path = self.root.join(format!(
            "{:08}_{phase}.json",
            self.next.fetch_add(1, Ordering::AcqRel)
        ));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        std::fs::File::open(&self.root)?.sync_all()
    }
}
fn normal_worker_stop(requested: bool, faulted: bool, expired: bool) -> bool {
    requested && !faulted && !expired
}
#[derive(Clone, Copy, Debug, serde::Serialize, PartialEq, Eq)]
pub struct NativePacketCounters {
    pub outbound_batches: u64,
    pub inbound_batches: u64,
    pub outbound_empty_batches: u64,
    pub inbound_empty_batches: u64,
    pub outbound_emitted_frames: u64,
    pub inbound_emitted_frames: u64,
}
#[derive(Default)]
struct AtomicPacketCounters {
    epoch: AtomicU64,
    outbound_batches: AtomicU64,
    inbound_batches: AtomicU64,
    outbound_empty_batches: AtomicU64,
    inbound_empty_batches: AtomicU64,
    outbound_emitted_frames: AtomicU64,
    inbound_emitted_frames: AtomicU64,
}
struct CounterWrite<'a>(&'a AtomicU64);
impl Drop for CounterWrite<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}
impl AtomicPacketCounters {
    // The owned packet worker is the sole writer; epoch publishes a coherent
    // public snapshot without exposing packet bytes, tuples or auth material.
    fn batch(&self, outbound: bool, empty: bool) -> io::Result<()> {
        let batches = if outbound {
            &self.outbound_batches
        } else {
            &self.inbound_batches
        };
        let empty_batches = if outbound {
            &self.outbound_empty_batches
        } else {
            &self.inbound_empty_batches
        };
        ensure(
            batches.load(Ordering::Relaxed) < 1_000_000,
            "packet batch counter bound",
        )?;
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let _finish = CounterWrite(&self.epoch);
        batches.fetch_add(1, Ordering::Relaxed);
        if empty {
            empty_batches.fetch_add(1, Ordering::Relaxed);
        }
        Ok(())
    }
    fn emitted(&self, outbound: bool) -> io::Result<()> {
        let frames = if outbound {
            &self.outbound_emitted_frames
        } else {
            &self.inbound_emitted_frames
        };
        ensure(
            frames.load(Ordering::Relaxed) < 64_000_000,
            "emitted frame counter bound",
        )?;
        self.epoch.fetch_add(1, Ordering::AcqRel);
        let _finish = CounterWrite(&self.epoch);
        frames.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn snapshot(&self) -> io::Result<NativePacketCounters> {
        for _ in 0..16 {
            let before = self.epoch.load(Ordering::Acquire);
            if before & 1 != 0 {
                std::hint::spin_loop();
                continue;
            }
            let snapshot = NativePacketCounters {
                outbound_batches: self.outbound_batches.load(Ordering::Acquire),
                inbound_batches: self.inbound_batches.load(Ordering::Acquire),
                outbound_empty_batches: self.outbound_empty_batches.load(Ordering::Acquire),
                inbound_empty_batches: self.inbound_empty_batches.load(Ordering::Acquire),
                outbound_emitted_frames: self.outbound_emitted_frames.load(Ordering::Acquire),
                inbound_emitted_frames: self.inbound_emitted_frames.load(Ordering::Acquire),
            };
            if self.epoch.load(Ordering::Acquire) == before {
                return Ok(snapshot);
            }
        }
        Err(refuse(
            "packet counter snapshot busy; no acceptance snapshot",
        ))
    }
}

// The stopped worker owns its original descriptors throughout this bounded
// wait; no new descriptor, thread, packet verdict, or fallback is created.
fn await_native_release(authorized: &AtomicBool, deadline: Instant) -> io::Result<()> {
    loop {
        ensure(
            Instant::now() < deadline,
            "native release independent deadline",
        )?;
        if authorized.load(Ordering::Acquire) {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn native_release_completion_permitted(
    now: Instant,
    deadline: Instant,
    faulted: bool,
) -> io::Result<()> {
    ensure(
        now < deadline && !faulted,
        "native release late or real fault retained",
    )
}
fn native_teardown_permitted(
    stopped: bool,
    requested: bool,
    faulted: bool,
    exited: bool,
) -> io::Result<()> {
    ensure(
        stopped && requested && !faulted && !exited,
        "native teardown requires normal stopped custody; failclosed rules retained",
    )
}
fn verify_owned_tun_absent(links: &Value, name: &str, index: u64) -> io::Result<()> {
    ensure(
        index > 0
            && index <= i32::MAX as u64
            && name.len() == 11
            && name.starts_with("agv")
            && name.as_bytes()[3..].iter().all(u8::is_ascii_hexdigit),
        "owned TUN deletion identity missing",
    )?;
    let rows = links
        .as_array()
        .ok_or_else(|| refuse("owned TUN deletion readback schema"))?;
    ensure(rows.len() <= 4096, "link deletion inventory bound")?;
    for row in rows {
        let n = row
            .get("ifname")
            .and_then(Value::as_str)
            .ok_or_else(|| refuse("link deletion inventory name missing"))?;
        let i = row
            .get("ifindex")
            .and_then(Value::as_u64)
            .ok_or_else(|| refuse("link deletion inventory index missing"))?;
        ensure(
            i > 0
                && i <= i32::MAX as u64
                && !n.is_empty()
                && n.len() <= 15
                && n != name
                && i != index,
            "owned TUN or recycled identity remains",
        )?;
    }
    Ok(())
}

pub struct LinuxRuntime {
    request: RelayOuterGenevaSettings,
    endpoints: Vec<SocketAddrV4>,
    table: String,
    tun_name: String,
    ifindex: u32,
    baseline_routes: Vec<RouteProof>,
    installed_authorization: Option<Arc<dyn InstalledGuardAuthorization>>,
    installed_policy_sha256: Option<[u8; 32]>,
    notifications: Mutex<Option<NotificationWatch>>,
    state: Mutex<State>,
    shutdown_fds: Mutex<BTreeMap<u64, Arc<OwnedFd>>>,
    retirement_requests: Mutex<BTreeSet<u64>>,
    failed: AtomicBool,
    stop_requested: AtomicBool,
    faulted: AtomicBool,
    counters: AtomicPacketCounters,
    worker_exited: AtomicBool,
    worker_handle: Mutex<Option<thread::JoinHandle<()>>>,
    worker_thread_joined: AtomicBool,
    packet_worker_stopped: AtomicBool,
    native_release_requested: AtomicBool,
    native_release_deadline: Mutex<Option<Instant>>,
    tun_ifindex: AtomicU64,
    local_alias: Mutex<Option<OwnedLocalAliasProof>>,
    deadline: Instant,
    journal: Arc<Journal>,
}
pub struct LinuxFlowGuard {
    runtime: Arc<LinuxRuntime>,
    token: u64,
}
impl Drop for LinuxFlowGuard {
    fn drop(&mut self) {
        self.close();
    }
}
impl RelaySocketGuard for LinuxFlowGuard {
    fn failed(&self) -> bool {
        self.runtime.is_failed()
    }
    fn close(&mut self) {
        if self.token != 0 {
            let token = std::mem::replace(&mut self.token, 0);
            let mut requests = match self.runtime.retirement_requests.lock() {
                Ok(value) => value,
                Err(poisoned) => poisoned.into_inner(),
            };
            requests.insert(token);
            drop(requests);
            let runtime = Arc::clone(&self.runtime);
            let failure = Arc::clone(&runtime);
            if thread::Builder::new()
                .name("aegis-relay-retire".into())
                .spawn(move || {
                    if runtime.close_flow(token).is_err() {
                        runtime.fail();
                    }
                })
                .is_err()
            {
                failure.fail();
            }
        }
    }
}
impl LinuxRuntime {
    pub fn start(
        request: &RelayOuterGenevaSettings,
        endpoints: Vec<SocketAddrV4>,
    ) -> io::Result<Arc<Self>> {
        Self::start_inner(request, endpoints, None)
    }
    pub fn start_with_installed_guard(
        request: &RelayOuterGenevaSettings,
        endpoints: Vec<SocketAddrV4>,
        authorization: Arc<dyn InstalledGuardAuthorization>,
    ) -> io::Result<Arc<Self>> {
        Self::start_inner(request, endpoints, Some(authorization))
    }
    fn start_inner(
        request: &RelayOuterGenevaSettings,
        mut endpoints: Vec<SocketAddrV4>,
        installed_authorization: Option<Arc<dyn InstalledGuardAuthorization>>,
    ) -> io::Result<Arc<Self>> {
        let startup_deadline = Instant::now() + Duration::from_secs(8);
        let _budget = OperationBudget::until(startup_deadline);
        endpoints.sort_unstable();
        endpoints.dedup();
        ensure(
            unsafe { libc::geteuid() } == 0,
            "relay native backend requires root",
        )?;
        ensure(
            !endpoints.is_empty()
                && endpoints.len() <= 16
                && request.max_duration_secs > 0
                && request.max_duration_secs <= 3600
                && request.outbound_queue != request.inbound_queue
                && request.socket_mark != 0,
            "native resource configuration refused",
        )?;
        ensure(
            request.strategy.len() <= 65536
                && request.strategy.is_ascii()
                && !request.local_address.is_unspecified()
                && !request.local_address.is_multicast()
                && !request.local_address.is_broadcast()
                && !request.local_address.is_loopback()
                && [request.local_mac, request.next_hop_mac]
                    .iter()
                    .all(|m| *m != [0; 6] && m[0] & 1 == 0)
                && endpoints.iter().all(|e| {
                    e.port() != 0
                        && !e.ip().is_unspecified()
                        && !e.ip().is_multicast()
                        && !e.ip().is_broadcast()
                        && !e.ip().is_loopback()
                        && *e.ip() != request.local_address
                }),
            "native tuple/configuration refused",
        )?;
        for endpoint in &endpoints {
            RelayGenevaProgram::new(
                &request.strategy,
                RelayFlowPin {
                    local: request.local_address,
                    relay: *endpoint.ip(),
                    local_port: 1,
                    relay_port: endpoint.port(),
                },
            )
            .map_err(|_| refuse("strategy refused before native setup"))?;
        }
        ensure(
            !request.interface.is_empty()
                && request.interface.len() <= 15
                && request
                    .interface
                    .bytes()
                    .all(|v| v.is_ascii_alphanumeric() || v == b'_' || v == b'-'),
            "native interface name refused",
        )?;
        build_source_stamp()?;
        let proof = route(request, endpoints[0], None)?;
        let mut baseline_routes = vec![proof.clone()];
        for endpoint in endpoints.iter().skip(1) {
            let other = route(request, *endpoint, None)?;
            ensure(
                other.ifindex == proof.ifindex,
                "endpoint route interface differs",
            )?;
            baseline_routes.push(other);
        }
        let token = format!("{:08x}", rand::thread_rng().next_u32());
        let table = format!("aegis_rg_{token}");
        let rules = json("nft", &["-j", "-n", "-y", "-p", "list", "ruleset"])?;
        let installed_proof = if let Some(authorization) = &installed_authorization {
            let snapshot = table_snapshot(&rules, "netdev", installed_guard::TABLE)?;
            let proof = authorization.verify(request, &endpoints, &snapshot)?;
            validate_installed_proof(&proof, &snapshot, build_source_stamp()?, request)?;
            let filtered = without_verified_tables(&rules, &[("netdev", installed_guard::TABLE)])?;
            validate_mark_reservation(&filtered, &table, request.socket_mark)?;
            Some(proof)
        } else {
            validate_mark_reservation(&rules, &table, request.socket_mark)?;
            None
        };
        let journal = Arc::new(Journal::new(&token)?);
        let _journal = JournalScope::enter(&journal);
        journal.record("setup_intent",serde_json::json!({"schema":"aegis_relay_geneva_native_intent_v1","instance":token,"process_identity":self_process_identity()?,"table":table,"tun":format!("agv{token}"),"request_public":{"interface":request.interface,"local_address":request.local_address,"local_mac":request.local_mac,"next_hop_mac":request.next_hop_mac,"socket_mark":request.socket_mark,"outbound_queue":request.outbound_queue,"inbound_queue":request.inbound_queue,"max_duration_secs":request.max_duration_secs},"endpoints_public":endpoints,"owned_flows":0,"strategy_sha256":hex::encode(sha2::Sha256::digest(request.strategy.as_bytes())),"executable_sha256":hex::encode(sha2::Sha256::digest(std::fs::read("/proc/self/exe")?)),"source_stamp":build_source_stamp()?,"controlled_native_acceptance":false}))?;
        if let Some(proof) = &installed_proof {
            journal.record("installed_guard_authorized", serde_json::json!({
                "source":proof.source_commit(),"family":proof.table_family(),"table":proof.table_name(),
                "interface":proof.interface(),"socket_mark":proof.socket_mark(),
                "table_sha256":hex::encode(proof.table_sha256()),"policy_sha256":hex::encode(proof.policy_sha256()),
                "same_ruleset_snapshot":true,"inet_table_exemption":false}))?;
        }
        let runtime = Arc::new(Self {
            request: request.clone(),
            endpoints,
            table,
            tun_name: format!("agv{token}"),
            ifindex: proof.ifindex,
            baseline_routes,
            installed_policy_sha256: installed_proof
                .as_ref()
                .map(InstalledGuardProof::policy_sha256),
            installed_authorization,
            notifications: Mutex::new(None),
            shutdown_fds: Mutex::new(BTreeMap::new()),
            retirement_requests: Mutex::new(BTreeSet::new()),
            state: Mutex::new(State {
                flows: BTreeMap::new(),
                retired: Vec::new(),
                next_token: 1,
                table_present: false,
                quiesced: false,
            }),
            failed: AtomicBool::new(false),
            stop_requested: AtomicBool::new(false),
            faulted: AtomicBool::new(false),
            counters: AtomicPacketCounters::default(),
            worker_exited: AtomicBool::new(false),
            worker_handle: Mutex::new(None),
            worker_thread_joined: AtomicBool::new(false),
            packet_worker_stopped: AtomicBool::new(false),
            native_release_requested: AtomicBool::new(false),
            native_release_deadline: Mutex::new(None),
            tun_ifindex: AtomicU64::new(0),
            local_alias: Mutex::new(None),
            deadline: Instant::now() + Duration::from_secs(u64::from(request.max_duration_secs)),
            journal,
        });
        let outcome = (|| -> io::Result<()> {
            operation_live()?;
            let native = match NativeIo::new(request, proof.ifindex, &token) {
                Ok(io) => io,
                Err(error) => {
                    let _=runtime.journal.record("setup_failed",serde_json::json!({"phase":"exclusive_native_resources","kind":format!("{:?}",error.kind())}));
                    return Err(error);
                }
            };
            ensure(
                native.tun_ifindex != proof.ifindex,
                "owned TUN identity equals physical interface",
            )?;
            runtime
                .tun_ifindex
                .store(u64::from(native.tun_ifindex), Ordering::Release);
            *lock(&runtime.local_alias)? = Some(native.local_alias.clone());
            runtime.journal.record("owned_existing_local32_proven",serde_json::json!({
                "existing_physical_address_only":true,"host_scope":true,"prefix_length":32,
                "noprefixroute":true,"no_broadcast_or_peer":true,"physical_first_local_route_unchanged":true,
                "full_local_route_delta_owned_alias_only":true,"host_global_rp_filter_unchanged":true,
                "owned_tun_rp_filter":2,"tun":runtime.tun_name,"owned_ifindex":native.tun_ifindex,
                "physical_ifindex":proof.ifindex,"physical_interface":request.interface,
                "local_address":request.local_address
            }))?;
            if let Err(error) = runtime.install_rules() {
                runtime.fail();
                let _=runtime.journal.record("setup_failed",serde_json::json!({"phase":"rules_arm","kind":format!("{:?}",error.kind()),"table_intent":true,"retain_evidence_and_unknown_rules":true}));
                return Err(error);
            };
            operation_live()?;
            *lock(&runtime.notifications)? = Some(NotificationWatch::new()?);
            {
                let state = lock(&runtime.state)?;
                runtime.check_table(&state)?;
                runtime.refresh_routes(&state)?;
                runtime.check_notifications(&state)?;
            }
            let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
            let worker = Arc::clone(&runtime);
            let handle = thread::Builder::new().name("aegis-relay-geneva".into()).spawn(move||{
   if std::panic::catch_unwind(std::panic::AssertUnwindSafe(||worker.worker(native,ready_sender))).is_err(){worker.fail();}
   if worker.journal.record("worker_terminal",serde_json::json!({"failed_closed":worker.is_failed(),"runtime_fault":worker.faulted.load(Ordering::Acquire),"normal_stop_requested":worker.stop_requested.load(Ordering::Acquire),"native_descriptors_dropped":true})).is_err(){worker.fail();}
   worker.worker_exited.store(true,Ordering::Release);
  }).map_err(|_|{runtime.fail();refuse("owned relay worker spawn refused; failclosed rules retained")})?;
            *lock(&runtime.worker_handle)? = Some(handle);
            if ready_receiver
                .recv_timeout(startup_deadline.saturating_duration_since(Instant::now()))
                .is_err()
                || runtime.is_failed()
            {
                runtime.fail();
                let _ = runtime.journal.record(
                    "readiness_failed",
                    serde_json::json!({"retain_owned_table_and_journal":true}),
                );
                return Err(refuse(&format!(
                    "owned relay worker readiness refused; retained journal {}",
                    runtime.journal.root.display()
                )));
            }
            if let Err(error)=operation_live().and_then(|_|runtime.journal.record("ready",serde_json::json!({"worker_ready":true,"table":runtime.table,"tun":runtime.tun_name}))){runtime.fail();return Err(error)};
            Ok(())
        })();
        if let Err(error) = outcome {
            runtime.fail();
            let _=runtime.journal.record("setup_failed",serde_json::json!({"phase":"protected_native_start","kind":format!("{:?}",error.kind()),"reason":error.to_string(),"table_and_partial_flow_intent_retained":true}));
            return Err(io::Error::new(
                error.kind(),
                format!(
                    "{}; exact owned evidence {}",
                    error,
                    runtime.journal.root.display()
                ),
            ));
        }
        Ok(runtime)
    }
    pub fn instance_evidence_path(&self) -> &std::path::Path {
        &self.journal.root
    }
    pub fn is_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire) || Instant::now() >= self.deadline
    }
    pub fn packet_counters(&self) -> io::Result<NativePacketCounters> {
        self.counters.snapshot()
    }
    fn worker_live(&self) -> io::Result<()> {
        if normal_worker_stop(
            self.stop_requested.load(Ordering::Acquire),
            self.faulted.load(Ordering::Acquire),
            Instant::now() >= self.deadline,
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "owned requested normal worker stop",
            ));
        }
        ensure(
            !self.is_failed(),
            "owned worker failed/expired before operation",
        )
    }
    fn fail(&self) {
        self.stop_owned(true);
    }
    fn request_stop(&self) {
        self.stop_requested.store(true, Ordering::Release);
        self.stop_owned(false);
    }
    fn stop_owned(&self, fault: bool) {
        let first_fault = fault && !self.faulted.swap(true, Ordering::AcqRel);
        let first = !self.failed.swap(true, Ordering::AcqRel);
        // This registry never contains metadata/helper I/O; shutdown cannot wait on
        // the packet/retirement state mutex. Poison only recovers already-owned FDs.
        let fds = match self.shutdown_fds.lock() {
            Ok(fds) => fds,
            Err(poisoned) => poisoned.into_inner(),
        };
        for fd in fds.values() {
            unsafe {
                libc::shutdown(fd.as_raw_fd(), libc::SHUT_RDWR);
            }
        }
        let count = fds.len();
        drop(fds);
        if first_fault {
            let _=self.journal.record("runtime_fault",serde_json::json!({"normal_stop_requested":self.stop_requested.load(Ordering::Acquire),"real_fault_not_hidden_by_normal_stop":true}));
        }

        if let Ok(mut state) = self.state.try_lock() {
            for flow in state.flows.values_mut() {
                flow.program.close();
            }
        }
        if first {
            let _=self.journal.record("fail_closed",serde_json::json!({"owned_socket_count":count,"rules_retained_until_checked_quiescence":true,"runtime_fault":self.faulted.load(Ordering::Acquire),"normal_stop_requested":self.stop_requested.load(Ordering::Acquire)}));
        }
    }
    fn install_rules(&self) -> io::Result<()> {
        let script = super::linux_policy::render(&self.table, &self.tun_name, &self.request)?;
        lock(&self.state)?.table_present = true;
        self.journal.record("rules_arm_intent",serde_json::json!({"table":self.table,"script_sha256":hex::encode(sha2::Sha256::digest(&script))}))?;
        command("nft", &["-j", "-f", "-"], Some(&script))?;
        let state = lock(&self.state)?;
        self.check_table(&state).map(|_| ())
    }
    fn emitting_table_result<T>(&self, outcome: io::Result<T>) -> io::Result<T> {
        // Every selected readback failure, including command/snapshot/own-table
        // validation BEFORE callback, closes existing streams. Requested-stop
        // teardown is already non-emitting and must retain honest cleanup errors.
        if outcome.is_err()
            && self.installed_authorization.is_some()
            && !self.stop_requested.load(Ordering::Acquire)
        {
            self.fail();
        }
        outcome
    }
    fn check_table(&self, state: &State) -> io::Result<Vec<RelayFlowPin>> {
        self.emitting_table_result(self.check_table_inner(state))
    }
    fn check_table_inner(&self, state: &State) -> io::Result<Vec<RelayFlowPin>> {
        let rules = if self.installed_authorization.is_some() {
            Some(json("nft", &["-j", "-n", "-y", "-p", "list", "ruleset"])?)
        } else {
            None
        };
        let value = if let Some(rules) = &rules {
            table_snapshot(rules, "ip", &self.table)?
        } else {
            json(
                "nft",
                &["-j", "-n", "-y", "-p", "list", "table", "ip", &self.table],
            )?
        };
        let observed = super::linux_policy::observed_flows(&value)?;
        let intents: Vec<_> = state
            .flows
            .values()
            .map(|flow| (flow.pin, flow.presence))
            .collect();
        validate_owned_elements(&observed, &intents)?;
        let _digest = super::linux_policy::validate(
            &value,
            &self.table,
            &self.tun_name,
            &self.request,
            &observed,
        )?;
        if let Some(rules) = rules {
            // Fault/normal-stop cleanup validates ONLY our exact owned table.
            // It may remove that table after socket terminal proof even if an
            // administrator blocked the external guard. No guard is removed.
            if !self.is_failed() {
                self.check_installed_rules(&rules)?;
            }
        }
        Ok(observed)
    }
    fn check_installed_rules(&self, rules: &Value) -> io::Result<()> {
        let outcome = (|| -> io::Result<()> {
            let snapshot = table_snapshot(rules, "netdev", installed_guard::TABLE)?;
            let proof = self
                .installed_authorization
                .as_ref()
                .ok_or_else(|| refuse("installed authorization absent"))?
                .verify(&self.request, &self.endpoints, &snapshot)?;
            validate_installed_proof(&proof, &snapshot, build_source_stamp()?, &self.request)?;
            ensure(
                Some(proof.policy_sha256()) == self.installed_policy_sha256,
                "installed policy identity drift",
            )?;
            let filtered = without_verified_tables(
                rules,
                &[("ip", &self.table), ("netdev", installed_guard::TABLE)],
            )?;
            validate_mark_reservation(&filtered, &self.table, self.request.socket_mark)
        })();
        // Even pre-registration refusal closes existing owned streams; no
        // caller may catch a failed authority check and continue old flows.
        if outcome.is_err() {
            self.fail();
        }
        outcome
    }
    // Same state lock serializes owned set mutations and packet emission. Event
    // sockets are bounded and kernel-bound; no external command is run on a clean
    // per-packet fast path. A benign pinned neighbor event forces full refresh.
    fn refresh_routes(&self, state: &State) -> io::Result<()> {
        lock(&self.local_alias)?
            .as_ref()
            .ok_or_else(|| refuse("owned local alias proof absent"))?
            .verify_live()?;
        for (addr, pinned) in self.endpoints.iter().zip(&self.baseline_routes) {
            let fresh = route(&self.request, *addr, None)?;
            ensure(
                fresh.ifindex == pinned.ifindex
                    && fresh.mtu == pinned.mtu
                    && fresh.via == pinned.via,
                "baseline relay route drift",
            )?;
        }
        for flow in state.flows.values().filter(|flow| !flow.retiring) {
            let fresh = route(
                &self.request,
                SocketAddrV4::new(flow.pin.relay, flow.pin.relay_port),
                Some(flow.pin.local_port),
            )?;
            ensure(
                fresh.ifindex == flow.route.ifindex
                    && fresh.mtu == flow.route.mtu
                    && fresh.via == flow.route.via,
                "registered relay route drift",
            )?;
        }
        Ok(())
    }
    fn check_notifications(&self, state: &State) -> io::Result<()> {
        let mut slot = lock(&self.notifications)?;
        let watch = slot
            .as_mut()
            .ok_or_else(|| refuse("notification monitor not ready"))?;
        watch.no_nft_change()?;
        let mut routes = self.baseline_routes.clone();
        routes.extend(state.flows.values().map(|f| f.route.clone()));
        let events = watch.route_events(&self.request, self.ifindex, &routes, &self.journal)?;
        if !events.is_empty() {
            self.check_table(state)?;
            self.refresh_routes(state)?;
            watch.no_nft_change()?;
            ensure(
                watch.route.receive()?.is_none(),
                "route changed again during canonical refresh",
            )?;
            watch.route_epoch = watch
                .route_epoch
                .checked_add(1)
                .ok_or_else(|| refuse("route epoch overflow"))?;
            self.journal.record("route_epoch_refreshed",serde_json::json!({"route_epoch":watch.route_epoch,"event_sha256":events,"neighbor_same_mac_interface_and_path":true,"canonical_table_and_all_pinned_routes_rechecked":true}))?;
        }
        Ok(())
    }
    fn mutate_element(&self, script: &str, pin: RelayFlowPin, add: bool) -> io::Result<()> {
        command_checked("nft", &["-f", "-"], Some(script.as_bytes()), |pid, name| {
            let mut slot = lock(&self.notifications)?;
            slot.as_mut()
                .ok_or_else(|| refuse("notification custody absent before mutation"))?
                .own_element(pid, name, &self.table, pin, add, &self.journal)
        })
        .map(|_| ())
    }
    pub async fn connect(
        self: &Arc<Self>,
        addr: SocketAddrV4,
    ) -> io::Result<(TcpStream, LinuxFlowGuard)> {
        ensure(
            !self.is_failed() && self.endpoints.contains(&addr),
            "unregistered endpoint or failed relay worker",
        )?;
        let runtime = Arc::clone(self);
        let (socket, mut guard) = tokio::task::spawn_blocking(move || runtime.register(addr))
            .await
            .map_err(|_| refuse("owned socket registration failed"))??;
        match tokio::time::timeout(
            Duration::from_secs(15),
            socket.connect(std::net::SocketAddr::V4(addr)),
        )
        .await
        {
            Ok(Ok(stream)) if !self.is_failed() => Ok((stream, guard)),
            Ok(Ok(stream)) => {
                drop(stream);
                guard.close();
                Err(refuse("protected relay worker failed during connect"))
            }
            Ok(Err(error)) => {
                guard.close();
                Err(error)
            }
            Err(_) => {
                guard.close();
                Err(refuse("protected relay connect deadline"))
            }
        }
    }
    fn register(self: &Arc<Self>, addr: SocketAddrV4) -> io::Result<(TcpSocket, LinuxFlowGuard)> {
        let _journal = JournalScope::enter(&self.journal);
        let _budget =
            OperationBudget::until(self.deadline.min(Instant::now() + Duration::from_secs(5)));
        ensure(
            !self.is_failed() && self.endpoints.contains(&addr),
            "flow registration after deadline/refusal",
        )?;
        let socket = TcpSocket::new_v4()?;
        option(socket.as_raw_fd(), libc::SO_MARK, &self.request.socket_mark)?;
        socket.bind(std::net::SocketAddr::V4(SocketAddrV4::new(
            self.request.local_address,
            0,
        )))?;
        let port = socket.local_addr()?.port();
        let proof = route(&self.request, addr, Some(port))?;
        let duplicate = Arc::new(owned_fd(unsafe {
            libc::fcntl(socket.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3)
        })?);
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        ensure(
            unsafe { libc::fstat(duplicate.as_raw_fd(), &mut metadata) } == 0,
            "owned socket inode absent",
        )?;
        let pin = RelayFlowPin {
            local: self.request.local_address,
            relay: *addr.ip(),
            local_port: port,
            relay_port: addr.port(),
        };
        let program = RelayGenevaProgram::new(&self.request.strategy, pin)
            .map_err(|_| refuse("flow strategy refused"))?;
        let token = {
            let mut state = lock(&self.state)?;
            ensure(
                !self.is_failed()
                    && !state.quiesced
                    && state.flows.len() < MAX_FLOWS
                    && state.next_token <= MAX_LIFETIME_FLOWS,
                "registered/lifetime flow bound",
            )?;
            ensure(
                registration_pin_available(
                    pin,
                    state.flows.values().map(|flow| flow.pin),
                    &state.retired,
                ),
                "tuple generation reuse refused",
            )?;
            self.check_table(&state)?;
            self.check_notifications(&state)?;
            let token = state.next_token;
            state.next_token = token
                .checked_add(1)
                .ok_or_else(|| refuse("flow token exhausted"))?;
            // Record owned socket BEFORE any ambiguous nft element mutation.
            lock(&self.shutdown_fds)?.insert(token, Arc::clone(&duplicate));
            state.flows.insert(
                token,
                Flow {
                    pin,
                    program,
                    duplicate: Some(duplicate),
                    inode: metadata.st_ino,
                    route: proof,
                    retiring: false,
                    presence: None,
                },
            );
            token
        };
        let mut guard = LinuxFlowGuard {
            runtime: Arc::clone(self),
            token,
        };
        let result = (|| -> io::Result<()> {
            let mut state = lock(&self.state)?;
            ensure(!self.is_failed(), "flow deadline before nft mutation")?;
            self.journal.record("flow_arm_intent",serde_json::json!({"token":token,"socket_inode":metadata.st_ino,"tuple":{"local":pin.local,"relay":pin.relay,"local_port":pin.local_port,"relay_port":pin.relay_port}}))?;
            let script = format!(
                "add element ip {} flows {{ {} . {} . {} . {} }}\n",
                self.table, pin.relay, pin.relay_port, pin.local, pin.local_port
            );
            self.mutate_element(&script, pin, true)?;
            state
                .flows
                .get_mut(&token)
                .ok_or_else(|| refuse("recorded flow missing"))?
                .presence = Some(true);
            ensure(!self.is_failed(), "flow deadline after nft mutation")?;
            self.check_table(&state)?;
            self.check_notifications(&state)?;
            self.journal.record("flow_arm_confirmed",serde_json::json!({"token":token,"socket_inode":metadata.st_ino,"tuple":pin_json(pin),"presence":true}))
        })();
        if let Err(error) = result {
            self.fail();
            drop(socket);
            guard.close();
            return Err(error);
        }
        Ok((socket, guard))
    }
    fn close_flow(&self, token: u64) -> io::Result<()> {
        let _journal = JournalScope::enter(&self.journal);
        let _budget = OperationBudget::until(Instant::now() + Duration::from_secs(3));
        let mut state = lock(&self.state)?;
        if !state.flows.contains_key(&token) {
            ensure(
                token > 0 && token < state.next_token,
                "unknown retirement token",
            )?;
            lock(&self.retirement_requests)?.remove(&token);
            return Ok(());
        }
        let (pin, inode) = {
            let flow = state
                .flows
                .get_mut(&token)
                .ok_or_else(|| refuse("flow token absent"))?;
            self.journal.record("flow_retire_intent",serde_json::json!({"token":token,"socket_inode":flow.inode,"tuple":pin_json(flow.pin),"element_presence":flow.presence,"kernel_inode_proof_pending":true}))?;
            flow.retiring = true;
            flow.program.close();
            if let Some(fd) = flow.duplicate.take() {
                lock(&self.shutdown_fds)?.remove(&token);
                let result = option(
                    fd.as_raw_fd(),
                    libc::SO_LINGER,
                    &libc::linger {
                        l_onoff: 1,
                        l_linger: 0,
                    },
                );
                drop(fd);
                if let Err(error) = result {
                    let _=self.journal.record("linger_failed",serde_json::json!({"token":token,"owned_duplicate_closed":true,"kernel_inode_proof_pending":true}));
                    return Err(error);
                }
            }
            (flow.pin, flow.inode)
        };
        operation_live()?;
        let deadline = finite_deadline(Duration::from_millis(500));
        loop {
            let file = std::fs::File::open("/proc/net/tcp")?;
            let mut bytes = Vec::new();
            file.take((MAX_COMMAND_BYTES + 1) as u64)
                .read_to_end(&mut bytes)?;
            ensure(
                bytes.len() <= MAX_COMMAND_BYTES,
                "socket readback resource bound",
            )?;
            let sockets =
                std::str::from_utf8(&bytes).map_err(|_| refuse("socket inventory encoding"))?;
            let present = sockets.lines().skip(1).any(|line| {
                line.split_whitespace()
                    .nth(9)
                    .and_then(|s| s.parse::<u64>().ok())
                    == Some(inode)
            });
            if !present {
                break;
            }
            ensure(
                Instant::now() < deadline,
                "owned socket still present; rules retained",
            )?;
            thread::sleep(Duration::from_millis(5));
        }
        let observed = self.check_table(&state)?;
        if observed.contains(&pin) {
            // Unknown delete outcome remains an exact owned 0-or-1 tuple intent.
            state
                .flows
                .get_mut(&token)
                .ok_or_else(|| refuse("retired token absent"))?
                .presence = None;
            let script = format!(
                "delete element ip {} flows {{ {} . {} . {} . {} }}\n",
                self.table, pin.relay, pin.relay_port, pin.local, pin.local_port
            );
            self.journal.record("flow_delete_intent",serde_json::json!({"token":token,"socket_inode":inode,"tuple":pin_json(pin),"last_socket_inode_absent":true,"element_presence":null}))?;
            self.mutate_element(&script, pin, false)?;
        }
        state
            .flows
            .get_mut(&token)
            .ok_or_else(|| refuse("retired token absent"))?
            .presence = Some(false);
        self.check_table(&state)?;
        self.check_notifications(&state)?;
        state.flows.remove(&token);
        state.retired.push(pin);
        lock(&self.retirement_requests)?.remove(&token);
        self.journal.record("flow_retired",serde_json::json!({"token":token,"socket_inode":inode,"tuple":pin_json(pin),"last_socket_inode_absent":true,"tuple_element_removed":true}))?;
        Ok(())
    }
    /// Stop first; wait for caller-owned streams/retirers and exact worker terminal.
    /// Unknown policy/socket state retains the failclosed table and durable journal.
    pub fn quiesce(&self) -> io::Result<()> {
        let _journal = JournalScope::enter(&self.journal);
        let deadline = Instant::now() + Duration::from_secs(10);
        let _budget = OperationBudget::until(deadline);
        self.request_stop();
        // A completed checked teardown is idempotent; expiry cannot turn the
        // prior exact join/link/route absence proof into an incomplete attempt.
        {
            let state = lock(&self.state)?;
            if state.quiesced {
                ensure(
                    state.flows.is_empty()
                        && !state.table_present
                        && self.worker_thread_joined.load(Ordering::Acquire)
                        && !self.faulted.load(Ordering::Acquire),
                    "completed quiescence state drift",
                )?;
                return Ok(());
            }
        }
        loop {
            ensure(
                Instant::now() < deadline,
                "protected relay quiescence deadline; exact teardown outcome unknown",
            )?;
            if self.packet_worker_stopped.load(Ordering::Acquire) {
                let release_deadline = lock(&self.native_release_deadline)?
                    .ok_or_else(|| refuse("stopped custody deadline absent"))?;
                let _custody_budget = OperationBudget::until(release_deadline);
                operation_live()?;
                let tokens: Vec<u64> = lock(&self.state)?.flows.keys().copied().collect();
                for token in tokens {
                    ensure(
                        !self.native_release_requested.load(Ordering::Acquire),
                        "native release preceded owned flow retirement",
                    )?;
                    self.close_flow(token)?;
                }
                let mut state = lock(&self.state)?;
                if state.quiesced {
                    ensure(
                        !self.faulted.load(Ordering::Acquire),
                        "quiescence cannot hide prior fault",
                    )?;
                    return Ok(());
                }
                ensure(
                    state.flows.is_empty(),
                    "owned flows remain before native release",
                )?;
                if !self.native_release_requested.load(Ordering::Acquire) {
                    ensure(
                        !self.worker_exited.load(Ordering::Acquire),
                        "native descriptors ended before checked teardown",
                    )?;
                    native_teardown_permitted(
                        self.packet_worker_stopped.load(Ordering::Acquire),
                        self.stop_requested.load(Ordering::Acquire),
                        self.faulted.load(Ordering::Acquire),
                        self.worker_exited.load(Ordering::Acquire),
                    )?;
                    if state.table_present {
                        self.check_table(&state)?;
                        native_teardown_permitted(
                            self.packet_worker_stopped.load(Ordering::Acquire),
                            self.stop_requested.load(Ordering::Acquire),
                            self.faulted.load(Ordering::Acquire),
                            self.worker_exited.load(Ordering::Acquire),
                        )?;
                        command("nft", &["delete", "table", "ip", &self.table], None)?;
                        let remaining = json("nft", &["-j", "-n", "-y", "-p", "list", "ruleset"])?;
                        ensure(
                            remaining
                                .get("nftables")
                                .and_then(Value::as_array)
                                .is_some_and(|rows| {
                                    rows.iter().all(|row| {
                                        row.get("table")
                                            .and_then(|v| v.get("name"))
                                            .and_then(Value::as_str)
                                            != Some(&self.table)
                                    })
                                }),
                            "owned table remains after deletion",
                        )?;
                        state.table_present = false;
                    }
                    ensure(
                        !state.table_present,
                        "owned table not absent before native release",
                    )?;
                    operation_live()?;
                    native_teardown_permitted(
                        self.packet_worker_stopped.load(Ordering::Acquire),
                        self.stop_requested.load(Ordering::Acquire),
                        self.faulted.load(Ordering::Acquire),
                        self.worker_exited.load(Ordering::Acquire),
                    )?;
                    let notifications = lock(&self.notifications)?
                        .take()
                        .ok_or_else(|| refuse("owned notification custody ended early"))?;
                    drop(notifications); // No route consumer remains when the exact owned TUN is destroyed.
                    self.journal.record("native_teardown_checked", serde_json::json!({
                        "owned_flows":0,"owned_table_removed":true,"notification_descriptors_closed":true,
                        "packet_worker_stopped":true,"release_request_only":true,
                        "tun":self.tun_name,"owned_ifindex":self.tun_ifindex.load(Ordering::Acquire)
                    }))?;
                    operation_live()?;
                    native_teardown_permitted(
                        self.packet_worker_stopped.load(Ordering::Acquire),
                        self.stop_requested.load(Ordering::Acquire),
                        self.faulted.load(Ordering::Acquire),
                        self.worker_exited.load(Ordering::Acquire),
                    )?;
                    self.native_release_requested.store(true, Ordering::Release);
                }
                drop(state);
                if self.worker_exited.load(Ordering::Acquire) {
                    let mut handle = lock(&self.worker_handle)?;
                    if let Some(owned) = handle.as_ref() {
                        if !owned.is_finished() {
                            drop(handle);
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        handle
                            .take()
                            .unwrap()
                            .join()
                            .map_err(|_| refuse("owned native worker join failed"))?;
                        self.worker_thread_joined.store(true, Ordering::Release);
                    }
                    drop(handle);
                    ensure(
                        self.worker_thread_joined.load(Ordering::Acquire),
                        "owned worker terminal join missing",
                    )?;
                    ensure(
                        !self.faulted.load(Ordering::Acquire),
                        "real native fault retained after resource teardown",
                    )?;
                    let index = self.tun_ifindex.load(Ordering::Acquire);
                    let links = json("ip", &["-j", "link", "show"])?;
                    verify_owned_tun_absent(&links, &self.tun_name, index)?;
                    lock(&self.local_alias)?
                        .as_ref()
                        .ok_or_else(|| refuse("owned local alias teardown proof absent"))?
                        .verify_removed()?;
                    let mut state = lock(&self.state)?;
                    ensure(
                        state.flows.is_empty() && !state.table_present,
                        "owned state drift after native release",
                    )?;
                    self.journal.record(
                        "quiesced",
                        serde_json::json!({
                            "owned_flows":0,"worker_terminal":true,"table_removed":true,
                            "owned_tun_removed":true,"notification_descriptors_closed":true,
                            "worker_thread_joined":true,"owned_local_alias_removed":true,
                            "physical_local_routes_restored":true,"tun":self.tun_name,"owned_ifindex":index
                        }),
                    )?;
                    state.quiesced = true;
                    return Ok(());
                }
            } else {
                ensure(
                    !self.worker_exited.load(Ordering::Acquire),
                    "native worker ended without stopped custody barrier",
                )?;
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
    fn worker(&self, mut native: NativeIo, ready: std::sync::mpsc::SyncSender<()>) {
        let _journal = JournalScope::enter(&self.journal);
        let result = (|| -> io::Result<()> {
            let _ready_budget =
                OperationBudget::until(self.deadline.min(Instant::now() + Duration::from_secs(3)));
            self.worker_live()?;
            {
                let state = lock(&self.state)?;
                self.check_table(&state)?;
            }
            ready
                .send(())
                .map_err(|_| refuse("owned readiness receiver gone"))?;
            drop(_ready_budget);
            let mut rng = rand::thread_rng();
            let mut received = 0usize;
            while !self.is_failed() {
                {
                    let state = lock(&self.state)?;
                    let _budget = OperationBudget::until(
                        self.deadline.min(Instant::now() + Duration::from_secs(3)),
                    );
                    self.check_notifications(&state)?;
                }
                for outbound in [true, false] {
                    let queue = if outbound {
                        &mut native.outbound
                    } else {
                        &mut native.inbound
                    };
                    let Some(datagram) = queue.packet()? else {
                        continue;
                    };
                    received = received
                        .checked_add(1)
                        .ok_or_else(|| refuse("packet counter exhausted"))?;
                    ensure(received <= 1_000_000, "native packet resource bound")?;
                    let _budget = OperationBudget::until(
                        self.deadline.min(Instant::now() + Duration::from_secs(3)),
                    );
                    let packet = queue::decode(
                        &datagram,
                        0,
                        false,
                        QueuePin {
                            queue: queue.number,
                            sequence: 0,
                            mark: self.request.socket_mark,
                            interface: self.ifindex,
                            hook: if outbound {
                                Hook::PostRouting
                            } else {
                                Hook::Input
                            },
                        },
                    )
                    .map_err(|_| refuse("queued packet ownership refused"))?;
                    let frame = ethernet_packet(
                        packet.payload,
                        packet.checksum_pending,
                        &self.request,
                        outbound,
                    )?;
                    let mut state = lock(&self.state)?;
                    let key = frame_pin(&frame, outbound)?;
                    if state
                        .flows
                        .values()
                        .any(|flow| flow.pin == key && flow.retiring)
                        || (!state.flows.values().any(|flow| flow.pin == key)
                            && state.retired.contains(&key))
                    {
                        self.worker_live()?;
                        queue.drop_original(packet.id)?;
                        continue;
                    }
                    self.check_notifications(&state)?;
                    let flow = state
                        .flows
                        .values_mut()
                        .find(|flow| {
                            flow.pin == key && !flow.retiring && flow.presence == Some(true)
                        })
                        .ok_or_else(|| refuse("queued tuple not actively registered"))?;
                    let mtu = flow.route.mtu;
                    let batch = flow
                        .program
                        .execute(
                            &frame,
                            if outbound {
                                RelayPacketDirection::Outbound
                            } else {
                                RelayPacketDirection::Inbound
                            },
                            &mut rng,
                        )
                        .map_err(|_| refuse("relay program refused whole batch"))?;
                    ensure(
                        batch.frames().iter().all(|f| f.len() - 14 <= mtu),
                        "generated frame exceeds pinned MTU",
                    )?;
                    self.worker_live()?;
                    self.check_notifications(&state)?;
                    let id = packet.id;
                    queue.drop_original(id)?;
                    self.counters.batch(outbound, batch.frames().is_empty())?;
                    for frame in batch.frames() {
                        self.worker_live()?;
                        self.check_notifications(&state)?;
                        native.emit(frame, outbound)?;
                        self.counters.emitted(outbound)?;
                    }
                }
            }
            Ok(())
        })();
        let normal_stop = matches!(&result,Err(e) if e.kind()==io::ErrorKind::Interrupted && e.to_string()=="owned requested normal worker stop")
            && normal_worker_stop(
                self.stop_requested.load(Ordering::Acquire),
                self.faulted.load(Ordering::Acquire),
                Instant::now() >= self.deadline,
            );
        if let Err(error) = result {
            if !normal_stop {
                self.fail();
                let _=self.journal.record("worker_failed",serde_json::json!({"kind":format!("{:?}",error.kind()),"reason":error.to_string(),"no_accept_fallback":true,"normal_stop_did_not_mask_fault":true}));
            }
        }
        if normal_stop
            || normal_worker_stop(
                self.stop_requested.load(Ordering::Acquire),
                self.faulted.load(Ordering::Acquire),
                Instant::now() >= self.deadline,
            )
        {
            self.stop_owned(false)
        } else {
            self.fail()
        }
        // Keep the existing NativeIo custody on this stopped worker. No packet
        // read/emit occurs below. Its own deadline is independent of any caller.
        let release_deadline = Instant::now() + Duration::from_secs(10);
        match lock(&self.native_release_deadline) {
            Ok(mut slot) => *slot = Some(release_deadline),
            Err(_) => {
                self.fail();
                return;
            }
        }
        if self
            .journal
            .record(
                "packet_worker_stopped",
                serde_json::json!({
                    "packet_emission_stopped":true,"native_descriptors_still_owned":true,
                    "owned_tun_still_owned":true,"release_window_milliseconds":10000,
                    "normal_stop_requested":self.stop_requested.load(Ordering::Acquire),
                    "runtime_fault":self.faulted.load(Ordering::Acquire)
                }),
            )
            .is_err()
        {
            self.fail();
            return;
        }
        self.packet_worker_stopped.store(true, Ordering::Release);
        let release = await_native_release(&self.native_release_requested, release_deadline)
            .and_then(|()| native_release_completion_permitted(Instant::now(), release_deadline,
                self.faulted.load(Ordering::Acquire)))
            .and_then(|()| {
                // Only this actual NativeIo owner asserts descriptor custody.
                self.journal.record("native_release_authorized", serde_json::json!({
                    "owned_flows":0,"owned_table_removed":true,"notification_descriptors_closed":true,
                    "packet_worker_stopped":true,"native_descriptors_still_owned":true,
                    "original_release_deadline_checked_before_record":true,
                    "tun":self.tun_name,"owned_ifindex":native.tun_ifindex
                }))
            })
            .and_then(|()| native_release_completion_permitted(Instant::now(), release_deadline,
                self.faulted.load(Ordering::Acquire)));
        if release.is_err() {
            self.fail();
            let _ = self.journal.record("native_release_deadline_failed", serde_json::json!({
                "checked_release_authorization_failed":true,
                "original_release_deadline_elapsed":Instant::now() >= release_deadline,
                "release_window_milliseconds":10000,"real_fault_not_hidden":true,
                "no_unchecked_rule_deletion":true,
                "last_checked_owned_table_present_state":self.state.try_lock().ok().map(|state| state.table_present),
                "durable_failure_evidence_retained":true
            }));
        }
        // Actual NativeIo descriptor drop occurs here, before worker_terminal.
    }
}
#[cfg(test)]
mod tests {
    #[test]
    fn native_source_stamp_is_validated_and_process_immutable() {
        let cell = std::sync::OnceLock::new();
        assert!(super::bind_source_stamp(&cell, "unknown").is_err());
        assert!(cell.get().is_none());
        let first = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert!(super::bind_source_stamp(&cell, first).is_ok());
        assert!(super::bind_source_stamp(&cell, first).is_ok());
        assert!(
            super::bind_source_stamp(&cell, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").is_err()
        );
        assert_eq!(cell.get(), Some(&first));
    }

    use super::*;
    #[test]
    fn owned_existing_local32_fd_identity_refuses_foreign_persistent_or_changed_link() {
        assert!(owned_tun_identity_fields(b"agvf06014e8", 0x1001, "agvf06014e8", 4).is_ok());
        assert!(owned_tun_identity_fields(b"client0", 0x1001, "agvf06014e8", 3).is_err());
        assert!(owned_tun_identity_fields(b"agv00000000", 0x1001, "agvf06014e8", 4).is_err());
        assert!(owned_tun_identity_fields(b"agvf06014e8", 0x1801, "agvf06014e8", 4).is_err());
        assert!(owned_tun_identity_fields(b"agvf06014e8", 0x1001, "agvf06014e8", 0).is_err());
    }
    fn alias_route_fixture(dev: &str) -> Value {
        serde_json::json!({"type":"local","dst":"192.0.2.2","dev":dev,"protocol":"kernel","scope":"host","prefsrc":"192.0.2.2","flags":[]})
    }
    #[test]
    fn owned_existing_local32_route_delta_preserves_original_first_alias() {
        let ip = "192.0.2.2".parse().unwrap();
        let original = serde_json::json!([alias_route_fixture("client0")]);
        let after = serde_json::json!([
            alias_route_fixture("client0"),
            alias_route_fixture("agvf06014e8")
        ]);
        assert!(alias_baseline_eligible(&original, ip, "client0").is_ok());
        assert!(alias_routes_after(&original, &after, ip, "agvf06014e8").is_ok());
        assert!(alias_routes_after(&original, &original, ip, "agvf06014e8").is_err());
    }
    #[test]
    fn owned_existing_local32_refuses_foreign_route_or_duplicate_alias() {
        let ip = "192.0.2.2".parse().unwrap();
        let original = serde_json::json!([alias_route_fixture("client0")]);
        for after in [
            serde_json::json!([
                alias_route_fixture("foreign0"),
                alias_route_fixture("agvf06014e8")
            ]),
            serde_json::json!([
                alias_route_fixture("client0"),
                alias_route_fixture("agvf06014e8"),
                alias_route_fixture("agvf06014e8")
            ]),
        ] {
            assert!(alias_routes_after(&original, &after, ip, "agvf06014e8").is_err());
        }
        let both = serde_json::json!([
            alias_route_fixture("client0"),
            alias_route_fixture("other0")
        ]);
        assert!(alias_baseline_eligible(&both, ip, "client0").is_err());
        let mut unknown = alias_route_fixture("client0");
        unknown["nexthops"] = serde_json::json!([]);
        assert!(alias_baseline_eligible(&serde_json::json!([unknown]), ip, "client0").is_err());
    }
    #[test]
    fn owned_existing_local32_request_is_exclusive_host_noprefixroute() {
        let ip = "192.0.2.2".parse().unwrap();
        let bytes = own_local32_request(4, ip, 123).unwrap();
        assert_eq!(bytes.len(), 48);
        assert_eq!(&bytes[4..6], &20u16.to_ne_bytes());
        assert_eq!(&bytes[6..8], &0x605u16.to_ne_bytes());
        assert_eq!(&bytes[16..20], &[2, 32, 0, 254]);
        assert_eq!(&bytes[20..24], &4u32.to_ne_bytes());
        assert_eq!(&bytes[24..32], &[8, 0, 1, 0, 192, 0, 2, 2]);
        assert_eq!(&bytes[32..40], &[8, 0, 2, 0, 192, 0, 2, 2]);
        assert_eq!(&bytes[40..44], &[8, 0, 8, 0]);
        assert_eq!(&bytes[44..48], &0x200u32.to_ne_bytes());
        assert!(own_local32_request(0, ip, 123).is_err());
        assert!(own_local32_request(4, ip, 0).is_err());
        for forbidden in [
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::LOCALHOST,
            Ipv4Addr::BROADCAST,
            Ipv4Addr::new(224, 0, 0, 1),
        ] {
            assert!(own_local32_request(4, forbidden, 123).is_err());
        }
    }
    #[test]
    fn owned_existing_local32_exact_address_refuses_unknown_family_broadcast_peer() {
        let ip = "192.0.2.2".parse().unwrap();
        let row = serde_json::json!({"family":"inet","local":"192.0.2.2","prefixlen":32,"scope":"host","noprefixroute":true,"label":"agvf06014e8","valid_life_time":4294967295u64,"preferred_life_time":4294967295u64});
        let inventory =
            |v: Value| serde_json::json!([{"ifname":"agvf06014e8","ifindex":4,"addr_info":[v]}]);
        assert!(alias_address_readback(&inventory(row.clone()), ip, "agvf06014e8", 4).is_ok());
        for (key, value) in [
            ("prefixlen", serde_json::json!(24)),
            ("scope", serde_json::json!("global")),
            ("noprefixroute", serde_json::json!(false)),
            ("broadcast", serde_json::json!("192.0.2.255")),
            ("peer", serde_json::json!("192.0.2.3")),
            ("family", serde_json::json!("inet6")),
        ] {
            let mut changed = row.clone();
            changed[key] = value;
            assert!(alias_address_readback(&inventory(changed), ip, "agvf06014e8", 4).is_err());
        }
    }
    #[test]
    fn owned_existing_local32_refuses_vrf_master_wrong_physical_identity() {
        let link = serde_json::json!({"ifname":"client0","ifindex":3});
        assert!(
            alias_physical_link_eligible(&serde_json::json!([link.clone()]), "client0", 3).is_ok()
        );
        for (key, value) in [
            ("master", serde_json::json!("vrf0")),
            ("linkinfo", serde_json::json!({"info_kind":"vrf"})),
            ("ifindex", serde_json::json!(4)),
        ] {
            let mut changed = link.clone();
            changed[key] = value;
            assert!(
                alias_physical_link_eligible(&serde_json::json!([changed]), "client0", 3).is_err()
            );
        }
    }

    #[test]
    fn native_release_record_duration_cannot_mask_deadline_or_fault() {
        let now = Instant::now();
        assert!(
            native_release_completion_permitted(now, now + Duration::from_millis(1), false).is_ok()
        );
        assert!(native_release_completion_permitted(now, now, false).is_err());
        assert!(
            native_release_completion_permitted(now, now - Duration::from_millis(1), false)
                .is_err()
        );
        assert!(
            native_release_completion_permitted(now, now + Duration::from_secs(1), true).is_err()
        );
    }
    #[test]
    fn native_release_unconfirmed_expires_without_caller() {
        let authorized = AtomicBool::new(false);
        let start = Instant::now();
        assert!(await_native_release(&authorized, start + Duration::from_millis(12)).is_err());
        assert!(start.elapsed() >= Duration::from_millis(12));
        assert!(start.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn native_release_late_authorization_cannot_bypass_deadline() {
        assert!(await_native_release(
            &AtomicBool::new(true),
            Instant::now() - Duration::from_millis(1)
        )
        .is_err());
    }
    #[test]
    fn native_release_keeps_custody_until_checked_authorization() {
        struct Custody(Arc<AtomicBool>);
        impl Drop for Custody {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let authorized = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let worker_authorized = Arc::clone(&authorized);
        let worker_dropped = Arc::clone(&dropped);
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let worker = thread::spawn(move || {
            let _custody = Custody(worker_dropped);
            ready_tx.send(()).unwrap();
            await_native_release(&worker_authorized, Instant::now() + Duration::from_secs(2))
                .unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(!dropped.load(Ordering::Acquire));
        authorized.store(true, Ordering::Release);
        worker.join().unwrap();
        assert!(dropped.load(Ordering::Acquire));
    }
    #[test]
    fn native_teardown_refuses_prior_fault_and_early_descriptor_drop() {
        assert!(native_teardown_permitted(true, true, false, false).is_ok());
        for bits in 0..16 {
            let args = (bits & 1 != 0, bits & 2 != 0, bits & 4 != 0, bits & 8 != 0);
            if args != (true, true, false, false) {
                assert!(native_teardown_permitted(args.0, args.1, args.2, args.3).is_err());
            }
        }
    }
    #[test]
    fn owned_tun_absence_keeps_foreign_physical_links() {
        let links =
            serde_json::json!([{"ifname":"lo","ifindex":1},{"ifname":"client0","ifindex":3}]);
        assert!(verify_owned_tun_absent(&links, "agvf06014e8", 4).is_ok());
        assert!(verify_owned_tun_absent(&serde_json::json!([]), "agvf06014e8", 4).is_ok());
    }
    #[test]
    fn owned_tun_absence_refuses_live_or_recycled_identity() {
        for row in [
            serde_json::json!({"ifname":"agvf06014e8","ifindex":4}),
            serde_json::json!({"ifname":"agvf06014e8","ifindex":5}),
            serde_json::json!({"ifname":"foreign0","ifindex":4}),
        ] {
            assert!(verify_owned_tun_absent(&serde_json::json!([row]), "agvf06014e8", 4).is_err());
        }
    }
    #[test]
    fn owned_tun_absence_refuses_unknown_or_unbounded_inventory() {
        for links in [
            serde_json::json!({}),
            serde_json::json!([{}]),
            serde_json::json!([{"ifname":"client0","ifindex":0}]),
            serde_json::json!([{"ifname":"","ifindex":3}]),
            serde_json::json!([{"ifname":"0123456789abcdef","ifindex":3}]),
            serde_json::json!([{"ifname":"client0","ifindex":2147483648u64}]),
        ] {
            assert!(verify_owned_tun_absent(&links, "agvf06014e8", 4).is_err());
        }
        assert!(verify_owned_tun_absent(&serde_json::json!([]), "", 4).is_err());
        assert!(verify_owned_tun_absent(&serde_json::json!([]), "client0", 4).is_err());
        assert!(verify_owned_tun_absent(&serde_json::json!([]), "agvf06014e8", 0).is_err());
        let rows = vec![serde_json::json!({"ifname":"client0","ifindex":3}); 4097];
        assert!(verify_owned_tun_absent(&serde_json::json!(rows), "agvf06014e8", 4).is_err());
    }

    fn route_notice_fixture(kind: u16, count: usize) -> NoticeDatagram {
        let mut bytes = Vec::new();
        for _ in 0..count {
            bytes.extend_from_slice(&28u32.to_ne_bytes());
            bytes.extend_from_slice(&kind.to_ne_bytes());
            bytes.extend_from_slice(&0u16.to_ne_bytes());
            bytes.extend_from_slice(&0u32.to_ne_bytes());
            bytes.extend_from_slice(&0u32.to_ne_bytes());
            bytes.extend_from_slice(&[2, 0, 0, 0]);
            bytes.extend_from_slice(&7i32.to_ne_bytes());
            bytes.extend_from_slice(&[0, 0, 0, 0]);
        }
        NoticeDatagram { bytes, group: 1 }
    }
    #[test]
    fn route_wrong_group_metadata_preserves_origin_refusal_and_header_identity() {
        let data = route_notice_fixture(16, 1);
        let value = route_origin_refusal_metadata(&data, 5).unwrap();
        assert_eq!(value["group_mask"], 1);
        assert_eq!(value["required_group_mask"], 4);
        assert_eq!(value["pinned_ifindex"], 5);
        assert_eq!(value["headers"][0]["type"], 16);
        assert_eq!(value["headers"][0]["candidate_ifindex"], 7);
        assert_eq!(value["headers"][0]["message_length"], 28);
        assert_eq!(value["headers_complete"], true);
        assert_eq!(value["origin_accepted"], false);
        assert_eq!(value["candidate_interface_ownership_proven"], false);
    }
    #[test]
    fn route_neighbor_group_has_no_failure_metadata_and_no_new_acceptance() {
        let mut data = route_notice_fixture(28, 1);
        data.group = 4;
        assert!(route_origin_refusal_metadata(&data, 7).is_none());
        // This means only that the unchanged neighbor validator must run next.
        data.group = 16;
        assert_eq!(
            route_origin_refusal_metadata(&data, 7).unwrap()["origin_accepted"],
            false
        );
    }
    #[test]
    fn route_metadata_64_header_bound_and_incomplete_overquota() {
        let data = route_notice_fixture(16, 64);
        let value = route_origin_refusal_metadata(&data, 7).unwrap();
        assert_eq!(value["headers"].as_array().unwrap().len(), 64);
        assert_eq!(value["headers_complete"], true);
        assert!(serde_json::to_vec(&value).unwrap().len() < 16384);
        let value = route_origin_refusal_metadata(&route_notice_fixture(16, 65), 7).unwrap();
        assert_eq!(value["headers_complete"], false);
        assert!(value["headers"].as_array().unwrap().is_empty());
    }
    #[test]
    fn route_metadata_malformed_length_is_explicitly_incomplete() {
        let mut data = route_notice_fixture(16, 1);
        data.bytes[..4].copy_from_slice(&1000u32.to_ne_bytes());
        let value = route_origin_refusal_metadata(&data, 7).unwrap();
        assert_eq!(value["headers_complete"], false);
        assert_eq!(value["datagram_within_bound"], true);
        assert!(value["headers"].as_array().unwrap().is_empty());
        assert_eq!(value["datagram_length"], 28);
    }
    #[test]
    fn route_metadata_never_exports_body_or_invents_route_ifindex() {
        let mut data = route_notice_fixture(24, 1);
        data.bytes[16..].copy_from_slice(b"INERT_SECRET");
        let value = route_origin_refusal_metadata(&data, 7).unwrap();
        assert!(value["headers"][0]["candidate_ifindex"].is_null());
        assert!(!serde_json::to_string(&value)
            .unwrap()
            .contains("INERT_SECRET"));
        assert_eq!(value["raw_body_retained"], false);
        assert_eq!(
            value["datagram_sha256"],
            hex::encode(sha2::Sha256::digest(&data.bytes))
        );
    }
    #[test]
    fn route_metadata_oversized_datagram_does_not_hash_or_export_payload() {
        let data = NoticeDatagram {
            bytes: vec![0; 65537],
            group: 1,
        };
        let value = route_origin_refusal_metadata(&data, 7).unwrap();
        assert_eq!(value["datagram_within_bound"], false);
        assert_eq!(value["headers_complete"], false);
        assert!(value["datagram_sha256"].is_null());
        assert!(serde_json::to_vec(&value).unwrap().len() < 1024);
    }

    #[test]
    fn directional_counters_drop_emission_snapshot_and_bounds() {
        let counters = AtomicPacketCounters::default();
        counters.batch(true, true).unwrap();
        counters.batch(false, false).unwrap();
        counters.emitted(false).unwrap();
        assert_eq!(
            counters.snapshot().unwrap(),
            NativePacketCounters {
                outbound_batches: 1,
                inbound_batches: 1,
                outbound_empty_batches: 1,
                inbound_empty_batches: 0,
                outbound_emitted_frames: 0,
                inbound_emitted_frames: 1
            }
        );
        counters
            .outbound_batches
            .store(1_000_000, Ordering::Relaxed);
        assert!(counters.batch(true, true).is_err());
        assert_eq!(counters.outbound_empty_batches.load(Ordering::Relaxed), 1);
        counters
            .outbound_emitted_frames
            .store(64_000_000, Ordering::Relaxed);
        assert!(counters.emitted(true).is_err());
        counters.epoch.store(1, Ordering::Release);
        assert!(counters.snapshot().is_err());
    }
    #[test]
    fn requested_stop_never_masks_prior_fault_or_deadline() {
        assert!(normal_worker_stop(true, false, false));
        assert!(!normal_worker_stop(false, false, false));
        assert!(!normal_worker_stop(true, true, false));
        assert!(!normal_worker_stop(true, false, true));
    }

    fn notice_fixture(kind: u16, port: u32, generation: u32, attrs: &[u8]) -> Vec<u8> {
        let mut b = vec![0; 20];
        b[4..6].copy_from_slice(&kind.to_ne_bytes());
        b[12..16].copy_from_slice(&port.to_ne_bytes());
        b[16] = if kind == 0x0a0f { 0 } else { 2 };
        b[18..20].copy_from_slice(&(generation as u16).to_be_bytes());
        b.extend(attrs);
        finish(&mut b);
        b
    }
    fn generation_fixture(port: u32, generation: u32, pid: u32) -> Vec<u8> {
        let mut a = Vec::new();
        attr(&mut a, 1, &generation.to_be_bytes());
        attr(&mut a, 2, &pid.to_be_bytes());
        attr(&mut a, 3, b"nft\0");
        notice_fixture(0x0a0f, port, generation, &a)
    }
    fn tuple_fixture(
        port: u32,
        generation: u32,
        pin: RelayFlowPin,
        add: bool,
        table: &str,
    ) -> Vec<u8> {
        let mut raw = Vec::new();
        raw.extend(pin.relay.octets());
        raw.extend(pin.relay_port.to_be_bytes());
        raw.extend([0, 0]);
        raw.extend(pin.local.octets());
        raw.extend(pin.local_port.to_be_bytes());
        raw.extend([0, 0]);
        let mut key = Vec::new();
        attr(&mut key, 1, &raw);
        let mut elem = Vec::new();
        attr(&mut elem, 1, &key);
        let mut list = Vec::new();
        attr(&mut list, 1, &elem);
        let mut a = Vec::new();
        let mut t = table.as_bytes().to_vec();
        t.push(0);
        attr(&mut a, 1, &t);
        attr(&mut a, 2, b"flows\0");
        attr(&mut a, 3, &list);
        notice_fixture(if add { 0x0a0c } else { 0x0a0e }, port, generation, &a)
    }
    fn expectation() -> OwnedNftExpectation<'static> {
        OwnedNftExpectation {
            generation: 42,
            pid: 71,
            name: "nft",
            table: "aegis_rg_owned",
            pin: pin(11),
            add: true,
            element_port: None,
            complete: false,
        }
    }
    #[test]
    fn nft_event_exact_actor_epoch_tuple_and_batched_commit() {
        let mut bytes = tuple_fixture(88, 42, pin(11), true, "aegis_rg_owned");
        bytes.extend(generation_fixture(88, 42, 71));
        let mut e = expectation();
        e.consume(&bytes).unwrap();
        assert!(e.complete);
        assert!(e.consume(&bytes).is_err());
        let mut split = expectation();
        split
            .consume(&tuple_fixture(88, 42, pin(11), true, "aegis_rg_owned"))
            .unwrap();
        assert!(!split.complete);
        split.consume(&generation_fixture(88, 42, 71)).unwrap();
        assert!(split.complete);
    }
    #[test]
    fn nft_foreign_gap_duplicate_and_trailing_events_refuse() {
        for invalid in [
            tuple_fixture(88, 42, pin(12), true, "aegis_rg_owned"),
            tuple_fixture(88, 42, pin(11), true, "foreign"),
            tuple_fixture(88, 41, pin(11), true, "aegis_rg_owned"),
            tuple_fixture(88, 42, pin(11), false, "aegis_rg_owned"),
            generation_fixture(88, 42, 71),
        ] {
            assert!(expectation().consume(&invalid).is_err());
        }
        for invalid in [
            generation_fixture(88, 42, 72),
            generation_fixture(89, 42, 71),
            generation_fixture(88, 43, 71),
            generation_fixture(88, 41, 71),
            tuple_fixture(88, 42, pin(11), true, "aegis_rg_owned"),
        ] {
            let mut e = expectation();
            e.consume(&tuple_fixture(88, 42, pin(11), true, "aegis_rg_owned"))
                .unwrap();
            assert!(e.consume(&invalid).is_err());
        }
        let mut trailing = tuple_fixture(88, 42, pin(11), true, "aegis_rg_owned");
        trailing.extend(generation_fixture(88, 42, 71));
        trailing.extend(generation_fixture(88, 42, 71));
        assert!(expectation().consume(&trailing).is_err());
        assert_eq!(next_nft_generation(u32::MAX), 1);
    }
    #[test]
    fn netlink_bounds_and_duplicate_attributes_refuse() {
        assert!(notice_messages(&[0; 15]).is_err());
        let mut short = generation_fixture(88, 42, 71);
        short[..4].copy_from_slice(&999u32.to_ne_bytes());
        assert!(notice_messages(&short).is_err());
        let mut a = Vec::new();
        attr(&mut a, 1, b"one\0");
        attr(&mut a, 1, b"two\0");
        assert!(notice_attrs(&a).is_err());
        assert!(notice_attrs(&[3, 0, 1, 0]).is_err());
    }
    #[test]
    fn benign_neighbor_is_pinned_not_blanket_event_ignore() {
        let runtime = no_io_runtime(
            owned_fd(unsafe {
                libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
            })
            .unwrap(),
        );
        let request = &runtime.request;
        let route = RouteProof {
            ifindex: 1,
            mtu: 1500,
            via: Ipv4Addr::new(192, 0, 2, 2),
        };
        for state in [2u16, 4, 8, 16, 128] {
            let mut b = vec![0; 12];
            b[0] = 2;
            b[4..8].copy_from_slice(&1u32.to_ne_bytes());
            b[8..10].copy_from_slice(&state.to_ne_bytes());
            b[11] = 1;
            attr(&mut b, 1, &route.via.octets());
            attr(&mut b, 2, &request.next_hop_mac);
            let row = NoticeMessage {
                kind: 28,
                flags: 0,
                sequence: 0,
                port: 0,
                body: &b,
            };
            assert!(admissible_neighbor(&row, request, 1, std::slice::from_ref(&route)).is_ok());
            assert!(admissible_neighbor(&row, request, 2, std::slice::from_ref(&route)).is_err());
            b[8..10].copy_from_slice(&32u16.to_ne_bytes());
            let row = NoticeMessage {
                kind: 28,
                flags: 0,
                sequence: 0,
                port: 0,
                body: &b,
            };
            assert!(admissible_neighbor(&row, request, 1, std::slice::from_ref(&route)).is_err());
        }
    }

    fn pin(port: u16) -> RelayFlowPin {
        RelayFlowPin {
            local: Ipv4Addr::new(192, 0, 2, 1),
            relay: Ipv4Addr::new(192, 0, 2, 2),
            local_port: port,
            relay_port: 443,
        }
    }
    #[test]
    fn ambiguous_owned_element_is_zero_or_one_but_foreign_never_adopted() {
        let own = pin(11);
        let foreign = pin(12);
        assert!(validate_owned_elements(&[], &[(own, None)]).is_ok());
        assert!(validate_owned_elements(&[own], &[(own, None)]).is_ok());
        assert!(validate_owned_elements(&[foreign], &[(own, None)]).is_err());
        assert!(validate_owned_elements(&[], &[(own, Some(true))]).is_err());
        assert!(validate_owned_elements(&[own], &[(own, Some(false))]).is_err());
    }
    #[test]
    fn tuple_generation_never_reuses_retired_or_live_pin() {
        let p = pin(11);
        assert!(!registration_pin_available(p, std::iter::empty(), &[p]));
        assert!(!registration_pin_available(p, [p].into_iter(), &[]));
        assert!(registration_pin_available(
            p,
            std::iter::empty(),
            &[pin(12)]
        ));
    }
    #[test]
    fn operation_budget_is_nested_and_shared_by_every_helper() {
        let outer = Instant::now() + Duration::from_secs(8);
        let _a = OperationBudget::until(outer);
        assert!(finite_deadline(Duration::from_secs(20)) <= outer);
        {
            let _b = OperationBudget::until(Instant::now() - Duration::from_millis(1));
            assert!(operation_live().is_err());
        }
        assert!(operation_live().is_ok());
    }
    #[test]
    fn reserved_mark_checks_hex_and_mask_intersection() {
        let rules = |left: Value, right: Value| serde_json::json!({"nftables":[{"rule":{"expr":[{"match":{"op":"==","left":left,"right":right}}]}}]});
        let mark = serde_json::json!({"meta":{"key":"mark"}});
        assert!(validate_mark_reservation(
            &rules(mark.clone(), serde_json::json!("0x400")),
            "aegis_rg_12345678",
            1024
        )
        .is_err());
        assert!(validate_mark_reservation(
            &rules(mark.clone(), serde_json::json!(1)),
            "aegis_rg_12345678",
            1024
        )
        .is_ok());
        let masked = serde_json::json!({"&":[mark,1024]});
        assert!(validate_mark_reservation(
            &rules(masked, serde_json::json!(1024)),
            "aegis_rg_12345678",
            1025
        )
        .is_err());
        assert!(validate_mark_reservation(&serde_json::json!({"nftables":[{"rule":{"expr":[{"mangle":{"key":{"meta":{"key":"mark"}},"value":1}}]}}]}),"aegis_rg_12345678",1024).is_err());
    }
    #[test]
    fn ack_binds_socket_port_not_kernel_header_zero() {
        let request = own_link_request(12, "agv12345678", 7, true).unwrap();
        let mut reply = vec![0; 36];
        reply[..4].copy_from_slice(&36u32.to_ne_bytes());
        reply[4..6].copy_from_slice(&2u16.to_ne_bytes());
        reply[6..8].copy_from_slice(&256u16.to_ne_bytes());
        reply[8..12].copy_from_slice(&7u32.to_ne_bytes());
        reply[12..16].copy_from_slice(&99u32.to_ne_bytes());
        reply[20..36].copy_from_slice(&request[..16]);
        assert!(exact_success_ack(&reply, &request, 99));
        assert!(!exact_success_ack(&reply, &request, 0));
        reply[16] = 1;
        assert!(!exact_success_ack(&reply, &request, 99));
    }
    #[test]
    fn own_link_message_does_not_encode_global_device_or_sysctl() {
        let request = own_link_request(12, "agv12345678", 7, true).unwrap();
        assert_eq!(u32::from_ne_bytes(request[20..24].try_into().unwrap()), 12);
        assert_eq!(u16::from_ne_bytes(request[4..6].try_into().unwrap()), 16);
        assert!(own_link_request(0, "all", 7, true).is_err());
        assert!(own_link_request(12, "../all", 7, true).is_err());
    }

    fn no_io_runtime(fd: OwnedFd) -> Arc<LinuxRuntime> {
        let request = RelayOuterGenevaSettings {
            strategy: String::new(),
            interface: "eth0".into(),
            local_address: Ipv4Addr::new(192, 0, 2, 1),
            local_mac: [2, 1, 2, 3, 4, 5],
            next_hop_mac: [2, 6, 7, 8, 9, 0],
            outbound_queue: 9,
            inbound_queue: 10,
            socket_mark: 1024,
            max_duration_secs: 60,
        };
        // Empty path cannot be a valid journal directory. These negative fixtures
        // never arm rules, invoke a helper, bind IP traffic or manufacture evidence.
        let journal = Arc::new(Journal {
            root: std::path::PathBuf::new(),
            inode: 0,
            device: 0,
            next: AtomicU64::new(0),
            normal_records: AtomicU64::new(0),
            terminal_records: AtomicU64::new(0),
            cleanup_records: AtomicU64::new(0),
            normal_bytes: AtomicU64::new(0),
            terminal_bytes: AtomicU64::new(0),
            cleanup_bytes: AtomicU64::new(0),
        });
        Arc::new(LinuxRuntime {
            request,
            endpoints: vec![],
            table: "aegis_rg_12345678".into(),
            tun_name: "agv12345678".into(),
            ifindex: 1,
            baseline_routes: Vec::new(),
            installed_authorization: None,
            installed_policy_sha256: None,
            notifications: Mutex::new(None),
            state: Mutex::new(State {
                flows: BTreeMap::new(),
                retired: vec![],
                next_token: 2,
                table_present: false,
                quiesced: false,
            }),
            shutdown_fds: Mutex::new([(1, Arc::new(fd))].into_iter().collect()),
            retirement_requests: Mutex::new(BTreeSet::new()),
            failed: AtomicBool::new(false),
            stop_requested: AtomicBool::new(false),
            faulted: AtomicBool::new(false),
            counters: AtomicPacketCounters::default(),
            worker_exited: AtomicBool::new(false),
            worker_handle: Mutex::new(None),
            worker_thread_joined: AtomicBool::new(false),
            packet_worker_stopped: AtomicBool::new(false),
            native_release_requested: AtomicBool::new(false),
            native_release_deadline: Mutex::new(None),
            tun_ifindex: AtomicU64::new(0),
            local_alias: Mutex::new(None),
            deadline: Instant::now() + Duration::from_secs(60),
            journal,
        })
    }
    #[test]
    fn fail_shuts_owned_unix_fd_while_metadata_state_lock_is_busy() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        let (a, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let runtime = no_io_runtime(owned_fd(a.into_raw_fd()).unwrap());
        let state = runtime.state.lock().unwrap();
        let worker = Arc::clone(&runtime);
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = thread::spawn(move || {
            worker.fail();
            tx.send(()).unwrap();
        });
        let result = rx.recv_timeout(Duration::from_millis(500));
        drop(state);
        handle.join().unwrap();
        assert!(result.is_ok(), "fail waited on metadata lock");
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
        assert!(runtime.is_failed());
    }
    #[test]
    fn cancelled_guard_retains_owned_retirement_intent_and_closes_on_cleanup_error() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        let (a, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let runtime = no_io_runtime(owned_fd(a.into_raw_fd()).unwrap());
        let fd = Arc::clone(runtime.shutdown_fds.lock().unwrap().get(&1).unwrap());
        let p = pin(11);
        let program = RelayGenevaProgram::new("", p).unwrap();
        let mut meta: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut meta) }, 0);
        runtime.state.lock().unwrap().flows.insert(
            1,
            Flow {
                pin: p,
                program,
                duplicate: Some(fd),
                inode: meta.st_ino,
                route: RouteProof {
                    ifindex: 1,
                    mtu: 1500,
                    via: p.relay,
                },
                retiring: false,
                presence: None,
            },
        );
        drop(LinuxFlowGuard {
            runtime: Arc::clone(&runtime),
            token: 1,
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while !runtime.is_failed() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(runtime.is_failed());
        assert!(runtime.retirement_requests.lock().unwrap().contains(&1));
        assert!(!runtime.state.lock().unwrap().table_present);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }
    #[test]
    fn netlink_drop_has_only_drop_verdict() {
        let mut b = message(0x301, 9, 17);
        let mut v = vec![0; 4];
        v.extend(33u32.to_be_bytes());
        attr(&mut b, 2, &v);
        finish(&mut b);
        assert_eq!(&b[24..28], &[0; 4]);
        assert_eq!(&b[28..32], &33u32.to_be_bytes());
        assert_eq!(u16::from_ne_bytes(b[4..6].try_into().unwrap()), 0x301);
    }
    #[test]
    fn reaped_or_uncertain_child_never_signals_numeric_group() {
        assert!(can_signal_group(true, true, true));
        for (v, w, g) in [
            (false, true, true),
            (true, false, true),
            (true, true, false),
        ] {
            assert!(!can_signal_group(v, w, g));
        }
    }
    #[test]
    fn checksum_known_vectors() {
        assert_eq!(checksum(&[0, 1, 255, 254]), 0);
        assert_eq!(checksum(&[1]), 0xfeff);
    }
    #[test]
    fn invalid_original_does_not_alias_or_repair() {
        let req = RelayOuterGenevaSettings {
            strategy: String::new(),
            interface: "eth0".into(),
            local_address: Ipv4Addr::new(192, 0, 2, 1),
            local_mac: [2, 1, 2, 3, 4, 5],
            next_hop_mac: [2, 6, 7, 8, 9, 0],
            outbound_queue: 9,
            inbound_queue: 10,
            socket_mark: 4,
            max_duration_secs: 1,
        };
        assert!(ethernet_packet(&[0; 40], false, &req, true).is_err());
    }
    fn installed_inputs() -> (
        installed_guard::PublicGuardPolicy,
        RelayOuterGenevaSettings,
        Vec<SocketAddrV4>,
        installed_guard::CurrentClientBinding,
    ) {
        let endpoints = vec!["192.0.2.3:24443".parse().unwrap()];
        let policy = installed_guard::PublicGuardPolicy {
            schema: "aegis_relay_geneva_installed_guard_v1".into(),
            source_commit: "a".repeat(40),
            interface: "client0".into(),
            local_address: "192.0.2.2".parse().unwrap(),
            socket_mark: 0x5a71,
            relay_endpoints: endpoints.clone(),
            device_guard_state_sha256: "b".repeat(64),
        };
        let request = RelayOuterGenevaSettings {
            strategy: "[IP:ttl:64]-drop-|".into(),
            interface: policy.interface.clone(),
            local_address: policy.local_address,
            local_mac: [2, 0, 0, 0, 0, 2],
            next_hop_mac: [2, 0, 0, 0, 0, 3],
            outbound_queue: 431,
            inbound_queue: 432,
            socket_mark: policy.socket_mark,
            max_duration_secs: 24,
        };
        let binding = installed_guard::CurrentClientBinding {
            boot_id: "00000000-0000-0000-0000-000000000000".into(),
            invocation_id: "c".repeat(32),
            cgroup_path: "/system.slice/aegis-client.service".into(),
            cgroup_inode: 42,
        };
        (policy, request, endpoints, binding)
    }
    #[test]
    fn installed_whitelist_exact_family_table_and_unknown_mark_refusal() {
        let (policy, request, endpoints, binding) = installed_inputs();
        let guard = installed_guard::expected(&policy, Some(&binding)).unwrap();
        let proof = installed_guard::verify_observation(
            &guard,
            &policy,
            Some(&binding),
            &policy.source_commit,
            &request,
            &endpoints,
        )
        .unwrap();
        validate_installed_proof(&proof, &guard, &policy.source_commit, &request).unwrap();
        assert!(validate_mark_reservation(&guard, "aegis_rg_owned", request.socket_mark).is_err());
        let empty = without_verified_tables(&guard, &[("netdev", installed_guard::TABLE)]).unwrap();
        validate_mark_reservation(&empty, "aegis_rg_owned", request.socket_mark).unwrap();
        for (family, table) in [
            ("inet", installed_guard::TABLE),
            ("netdev", "aegis_relay_geneva_device_guard_foreign"),
        ] {
            let mut rules = guard.clone();
            rules["nftables"].as_array_mut().unwrap().push(serde_json::json!({"rule":{"family":family,"table":table,"expr":[{"match":{"left":{"meta":{"key":"mark"}},"op":"==","right":request.socket_mark}}]}}));
            let selected = table_snapshot(&rules, "netdev", installed_guard::TABLE).unwrap();
            validate_installed_proof(&proof, &selected, &policy.source_commit, &request).unwrap();
            let filtered =
                without_verified_tables(&rules, &[("netdev", installed_guard::TABLE)]).unwrap();
            assert!(
                validate_mark_reservation(&filtered, "aegis_rg_owned", request.socket_mark)
                    .is_err()
            );
        }
    }
    #[test]
    fn installed_stale_proof_same_count_drift_and_source_refused() {
        let (policy, request, endpoints, binding) = installed_inputs();
        let guard = installed_guard::expected(&policy, Some(&binding)).unwrap();
        let proof = installed_guard::verify_observation(
            &guard,
            &policy,
            Some(&binding),
            &policy.source_commit,
            &request,
            &endpoints,
        )
        .unwrap();
        let mut drift = guard.clone();
        let last = drift["nftables"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap();
        let expr = last["rule"]["expr"]
            .as_array_mut()
            .unwrap()
            .last_mut()
            .unwrap();
        *expr = serde_json::json!({"accept":null});
        assert!(validate_installed_proof(&proof, &drift, &policy.source_commit, &request).is_err());
        assert!(installed_guard::verify_observation(
            &drift,
            &policy,
            Some(&binding),
            &policy.source_commit,
            &request,
            &endpoints
        )
        .is_err());
        assert!(validate_installed_proof(&proof, &guard, &"d".repeat(40), &request).is_err());
        let mut changed = request.clone();
        changed.socket_mark += 1;
        assert!(validate_installed_proof(&proof, &guard, &policy.source_commit, &changed).is_err());
    }
    #[test]
    fn installed_same_snapshot_handle_normalization_does_not_adopt_other_family() {
        let (policy, request, endpoints, binding) = installed_inputs();
        let guard = installed_guard::expected(&policy, Some(&binding)).unwrap();
        let proof = installed_guard::verify_observation(
            &guard,
            &policy,
            Some(&binding),
            &policy.source_commit,
            &request,
            &endpoints,
        )
        .unwrap();
        let mut rules = guard.clone();
        for (i, row) in rules["nftables"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .enumerate()
        {
            row.as_object_mut()
                .unwrap()
                .values_mut()
                .next()
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert("handle".into(), Value::from(i as u64 + 1));
        }
        rules["nftables"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"table":{"family":"inet","name":installed_guard::TABLE}}));
        let selected = table_snapshot(&rules, "netdev", installed_guard::TABLE).unwrap();
        validate_installed_proof(&proof, &selected, &policy.source_commit, &request).unwrap();
        let kept = without_verified_tables(&rules, &[("netdev", installed_guard::TABLE)]).unwrap();
        assert_eq!(kept["nftables"].as_array().unwrap().len(), 1);
        assert_eq!(kept["nftables"][0]["table"]["family"], "inet");
        assert!(table_snapshot(&rules, "netdev", "missing").is_err());
        assert!(table_snapshot(
            &serde_json::json!({"nftables":[{"table":{},"rule":{}}]}),
            "netdev",
            installed_guard::TABLE
        )
        .is_err());
    }
    #[test]
    fn installed_authority_error_closes_existing_owned_fd_before_new_registration() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        struct RejectedAuthority;
        impl InstalledGuardAuthorization for RejectedAuthority {
            fn verify(
                &self,
                _: &RelayOuterGenevaSettings,
                _: &[SocketAddrV4],
                _: &Value,
            ) -> io::Result<InstalledGuardProof> {
                Err(refuse("controlled stale role refusal"))
            }
        }
        let (a, mut peer) = UnixStream::pair().unwrap();
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let mut runtime = no_io_runtime(owned_fd(a.into_raw_fd()).unwrap());
        Arc::get_mut(&mut runtime).unwrap().installed_authorization =
            Some(Arc::new(RejectedAuthority));
        let (policy, _, _, binding) = installed_inputs();
        let guard = installed_guard::expected(&policy, Some(&binding)).unwrap();
        let state = runtime.state.lock().unwrap();
        assert!(runtime.check_installed_rules(&guard).is_err());
        assert!(runtime.is_failed());
        assert!(runtime.faulted.load(Ordering::Acquire));
        assert!(
            state.flows.is_empty(),
            "no new flow may be tracked by failed authority"
        );
        drop(state);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).unwrap(), 0);
    }
    #[test]
    fn installed_query_snapshot_and_own_policy_errors_close_prior_streams() {
        use std::os::fd::IntoRawFd;
        use std::os::unix::net::UnixStream;
        struct RejectedAuthority;
        impl InstalledGuardAuthorization for RejectedAuthority {
            fn verify(
                &self,
                _: &RelayOuterGenevaSettings,
                _: &[SocketAddrV4],
                _: &Value,
            ) -> io::Result<InstalledGuardProof> {
                Err(refuse("callback must not be reached"))
            }
        }
        for phase in 0..3 {
            let (a, mut peer) = UnixStream::pair().unwrap();
            peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut runtime = no_io_runtime(owned_fd(a.into_raw_fd()).unwrap());
            Arc::get_mut(&mut runtime).unwrap().installed_authorization =
                Some(Arc::new(RejectedAuthority));
            let state = runtime.state.lock().unwrap();
            let outcome: io::Result<()> = match phase {
                0 => Err(refuse("injected failed exact ruleset command readback")),
                1 => table_snapshot(&serde_json::json!({"nftables":[]}), "ip", &runtime.table)
                    .map(|_| ()),
                _ => super::super::linux_policy::validate(
                    &serde_json::json!({"nftables":[]}),
                    &runtime.table,
                    &runtime.tun_name,
                    &runtime.request,
                    &[],
                )
                .map(|_| ()),
            };
            assert!(runtime.emitting_table_result(outcome).is_err());
            assert!(runtime.is_failed() && runtime.faulted.load(Ordering::Acquire));
            assert!(state.flows.is_empty());
            drop(state);
            let mut byte = [0];
            assert_eq!(peer.read(&mut byte).unwrap(), 0);
        }
    }
}

#[path = "recovery_linux.rs"]
pub mod recovery;
