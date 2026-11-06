#![allow(dead_code)]

use serde_json::Value;
use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Synthetic loopback fixture material, never a deployment credential.
pub const TEST_RELAY_AUTH_TOKEN: &str =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

/// Escape a path inserted inside an existing TOML basic string literal.
pub fn toml_path(path: &Path) -> String {
    path.to_string_lossy()
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
}

/// Match the private-file contract enforced when real binaries load fixtures.
pub fn write_private_file(
    path: impl AsRef<Path>,
    contents: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let path = path.as_ref();
        if path.exists() {
            fs::remove_file(path)?;
        }
        aegis_core::windows_file::write_private_new(path, contents.as_ref(), false)
    }
    #[cfg(not(windows))]
    {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        file.write_all(contents.as_ref())
    }
}

pub struct TestDir {
    path: PathBuf,
}

impl TestDir {
    pub fn new(prefix: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aegis-client-{prefix}-{}-{nonce}",
            std::process::id()
        ));
        #[allow(unused_mut)] // Unix sets the creation mode below.
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).expect("create private test dir");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if std::env::var_os("AEGIS_KEEP_TEST_DIRS").is_some() {
            return;
        }
        let _ = fs::remove_dir_all(&self.path);
    }
}

pub struct ChildGuard {
    child: Child,
    /// Where the client's stderr went, so a death can be explained.
    stderr_path: PathBuf,
}

impl ChildGuard {
    pub fn spawn(config_path: &Path, events_path: &Path) -> Self {
        Self::spawn_with_env(config_path, events_path, &[])
    }

    pub fn spawn_with_env(config_path: &Path, events_path: &Path, envs: &[(&str, &str)]) -> Self {
        let bin = std::env::var_os("CARGO_BIN_EXE_aegis-client").expect("client test binary");
        let mut command = Command::new(bin);
        command
            .arg("--config")
            .arg(config_path)
            // These schema tests intentionally inspect detailed runtime fields.
            // Product defaults remain private unless this flag is supplied.
            .arg("--diagnostic-logs")
            .arg("--runtime-events-jsonl")
            .arg(events_path)
            .arg("--exit-on-stdin-eof")
            .stdin(Stdio::piped())
            .stdout(Stdio::null());
        // Keep the client's stderr. Discarding it is why a dead client only
        // ever showed up as "connection reset" with no explanation.
        let stderr_path = events_path.with_extension("client.err");
        match std::fs::File::create(&stderr_path) {
            Ok(file) => {
                command.stderr(Stdio::from(file));
            }
            Err(_) => {
                command.stderr(Stdio::null());
            }
        }
        for (key, value) in envs {
            command.env(key, value);
        }
        let child = command.spawn().expect("spawn aegis-client");
        Self { child, stderr_path }
    }
}

impl ChildGuard {
    /// Wait only for this owned child; Drop retains bounded cleanup on timeout.
    pub fn wait_for_exit(
        &mut self,
        timeout: Duration,
    ) -> std::io::Result<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                return Ok(status);
            }
            if Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "owned client did not exit",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    /// Whatever the client wrote to stderr, for a panic message.
    pub fn stderr_tail(&self) -> String {
        fs::read_to_string(&self.stderr_path)
            .map(|text| {
                text.lines()
                    .rev()
                    .take(10)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        // A client that died takes its reason with it unless we say so here.
        if let Ok(Some(status)) = self.child.try_wait() {
            if !status.success() {
                eprintln!(
                    "aegis-client exited with {status}; stderr tail:\n{}",
                    self.stderr_tail()
                );
            }
        }
        let _ = self.child.stdin.take();
        let graceful_deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < graceful_deadline => {
                    thread::sleep(Duration::from_millis(50));
                }
                Ok(None) | Err(_) => break,
            }
        }
        if self.child.kill().is_ok() {
            let kill_deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match self.child.try_wait() {
                    Ok(Some(_)) => return,
                    Ok(None) if Instant::now() < kill_deadline => {
                        thread::sleep(Duration::from_millis(50));
                    }
                    Ok(None) | Err(_) => return,
                }
            }
        }
    }
}

/// Ports already handed out in this process.
///
/// `bind(0)` picks a free port, but the listener is a temporary: it is dropped
/// as soon as the port number has been read, so the port is free again and the
/// kernel may hand the very same one to the next caller.
static RESERVED_PORTS: Mutex<BTreeSet<u16>> = Mutex::new(BTreeSet::new());

/// How long a cross-process claim stays valid before it is treated as debris
/// from a killed run.
const PORT_CLAIM_TTL: Duration = Duration::from_secs(600);

/// Claim a port across *all* test binaries, not just this one.
///
/// `cargo test` runs test binaries concurrently, so an in-process set is not
/// enough: two processes each ask the kernel for a free port and can be given
/// the same one, after which two clients are told to listen there, one dies
/// with "address in use", and the other test talks to the wrong client. A
/// claim file in a shared directory is what makes the reservation visible
/// between processes.
fn claim_port_across_processes(port: u16) -> bool {
    let dir = std::env::temp_dir().join("aegis-test-port-claims");
    if fs::create_dir_all(&dir).is_err() {
        // Without a shared directory we simply fall back to the in-process set.
        return true;
    }
    let path = dir.join(port.to_string());
    let create = |path: &Path| {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .is_ok()
    };
    if create(&path) {
        return true;
    }
    // A claim left behind by a run that was killed must not sideline the port
    // forever.
    let stale = fs::metadata(&path)
        .and_then(|meta| meta.modified())
        .map(|modified| modified.elapsed().unwrap_or_default() > PORT_CLAIM_TTL)
        .unwrap_or(false);
    if stale {
        let _ = fs::remove_file(&path);
        return create(&path);
    }
    false
}

pub fn reserve_tcp_port() -> u16 {
    for _ in 0..256 {
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("reserve port")
            .local_addr()
            .expect("reserved addr")
            .port();
        let fresh_here = RESERVED_PORTS
            .lock()
            .expect("reserved ports lock")
            .insert(port);
        if fresh_here && claim_port_across_processes(port) {
            return port;
        }
    }
    panic!("could not find a port no test process has already reserved");
}

/// Drop the cross-process claim for `port`.
///
/// Called once something is listening there: from that moment the kernel will
/// not hand the port to anyone else, so holding the claim any longer would only
/// sideline a port that other runs could use.
fn release_port_claim(port: u16) {
    let path = std::env::temp_dir()
        .join("aegis-test-port-claims")
        .join(port.to_string());
    let _ = fs::remove_file(path);
}

pub fn wait_for_port(port: u16, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(("127.0.0.1", port)) {
            Ok(stream) => {
                release_port_claim(port);
                return stream;
            }
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => panic!("socks listener did not start on port {port}: {err}"),
        }
    }
}

pub fn read_jsonl_records(path: &Path) -> Option<Vec<Value>> {
    let text = fs::read_to_string(path).ok()?;
    let mut records = Vec::new();
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        records.push(serde_json::from_str(line).ok()?);
    }
    Some(records)
}

pub fn wait_for_event(path: &Path, event_code: &str, timeout: Duration) -> (Value, Vec<Value>) {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(records) = read_jsonl_records(path) {
            if let Some(record) = records
                .iter()
                .find(|record| record["event_code"] == event_code)
                .cloned()
            {
                return (record, records);
            }
        }
        assert!(
            Instant::now() < deadline,
            "missing event {event_code} in {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn wait_for_event_count(
    path: &Path,
    event_code: &str,
    expected_count: usize,
    timeout: Duration,
) -> Vec<Value> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(records) = read_jsonl_records(path) {
            let matches: Vec<Value> = records
                .iter()
                .filter(|record| record["event_code"] == event_code)
                .cloned()
                .collect();
            if matches.len() >= expected_count {
                return matches;
            }
        }
        assert!(
            Instant::now() < deadline,
            "missing {expected_count} events {event_code} in {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(100));
    }
}

pub fn socks_handshake(stream: &mut TcpStream, target: SocketAddr) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set write timeout");

    stream.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);

    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(
        &target
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .expect("ipv4")
            .octets(),
    );
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).expect("write connect request");

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).expect("read connect reply");
    assert_eq!(&reply[..2], b"\x05\x00");
}

pub fn event_codes(records: &[Value]) -> Vec<&str> {
    records
        .iter()
        .filter_map(|record| record["event_code"].as_str())
        .collect()
}

pub fn assert_socks_listener_healthy(port: u16) {
    let mut healthy = wait_for_port(port, Duration::from_secs(10));
    healthy
        .write_all(b"\x05\x01\x00")
        .expect("write healthy greeting");
    let mut greeting = [0u8; 2];
    healthy
        .read_exact(&mut greeting)
        .expect("read healthy greeting");
    assert_eq!(greeting, [0x05, 0x00]);
}

pub fn assert_no_event(records: &[Value], event_code: &str) {
    assert!(
        !records
            .iter()
            .any(|record| record["event_code"] == event_code),
        "{records:?}"
    );
}
