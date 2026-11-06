//! Packaging-bound selected Cargo graph, not compiler linkage or native completeness.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
#[cfg(unix)]
use std::process::Command;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
pub(crate) const LEAF: &str = "client-cargo-inventory.json";
const FEATURES: [&str; 3] = ["chrome-like-quic", "chrome-like-tls", "raw-socket"];
const LIMIT: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Component {
    key: String,
    name: String,
    version: String,
    source_kind: String,
    source_identity_sha256: String,
    features: Vec<String>,
    dependencies: Vec<String>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    schema: String,
    scope: String,
    native_payload_complete: bool,
    compiler_linkage_proven: bool,
    source_revision: String,
    target_triple: String,
    default_features: bool,
    requested_features: Vec<String>,
    cargo_lock_sha256: String,
    client_binary_sha256: String,
    cargo_metadata_sha256: String,
    producer: BuildRecord,
    root_component: String,
    components: Vec<Component>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BuildRecord {
    schema: String,
    source_revision: String,
    target_triple: String,
    cargo_lock_sha256: String,
    binary_sha256: String,
    default_features: bool,
    requested_features: Vec<String>,
    resolved_root_features: Vec<String>,
    compiler_artifact_message_sha256: String,
    build_message_stream_sha256: String,
    target_evidence: String,
}
const MESSAGE_LIMIT: usize = 16 * 1024 * 1024;
const BINARY_LIMIT: usize = 64 * 1024 * 1024;
fn bounded_regular(path: &Path, limit: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let before = file.metadata()?;
    require(
        before.is_file() && before.len() <= limit as u64,
        "input is nonregular or oversized",
    )?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    require(
        bytes.len() <= limit && bytes.len() as u64 == before.len(),
        "input size changed or exceeded bound",
    )?;
    Ok(bytes)
}
fn source_pins(root: &Path) -> Result<BTreeMap<std::path::PathBuf, String>> {
    ["Cargo.toml", "Cargo.lock", "aegis-client/Cargo.toml"]
        .into_iter()
        .map(|p| {
            let path = root.join(p);
            let digest = digest(&bounded_regular(&path, LIMIT)?);
            Ok((path, digest))
        })
        .collect()
}
fn verify_pins(pins: &BTreeMap<std::path::PathBuf, String>) -> Result<()> {
    for (path, expected) in pins {
        require(
            digest(&bounded_regular(path, LIMIT)?) == *expected,
            "producer source/input changed",
        )?;
    }
    Ok(())
}
#[cfg(unix)]
struct OwnedChild {
    child: std::process::Child,
    signal_allowed: bool,
    signalled: bool,
}
#[cfg(unix)]
impl OwnedChild {
    fn observe_exit(&mut self) -> std::io::Result<bool> {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // SAFETY: our direct child only; WNOWAIT reserves leader identity.
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                self.child.id() as libc::id_t,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                self.signal_allowed = false;
            }
            return Err(error);
        }
        Ok(info.si_signo != 0)
    }
    fn stop(&mut self) -> std::io::Result<()> {
        if !self.signal_allowed || self.signalled {
            return Ok(());
        }
        self.signalled = true;
        // SAFETY: process_group(0) creates this owned group, leader unreaped.
        let rc = unsafe { libc::kill(-(self.child.id() as libc::pid_t), libc::SIGKILL) };
        if rc < 0 {
            let error = std::io::Error::last_os_error();
            #[cfg(target_os = "macos")]
            if error.raw_os_error() == Some(libc::EPERM) && self.only_exited_leader() {
                return Ok(());
            }
            if error.raw_os_error() != Some(libc::ESRCH) {
                let _ = self.child.kill();
                return Err(error);
            }
        }
        Ok(())
    }
    #[cfg(target_os = "macos")]
    fn only_exited_leader(&mut self) -> bool {
        if !matches!(self.observe_exit(), Ok(true)) {
            return false;
        }
        let mut members = [0 as libc::pid_t; 2];
        // SAFETY: exact owned group query writes at most two initialized PIDs.
        let (count, errno) = unsafe {
            *libc::__error() = 0;
            let count = libc::proc_listpgrppids(
                self.child.id() as libc::pid_t,
                members.as_mut_ptr().cast(),
                std::mem::size_of_val(&members) as libc::c_int,
            );
            (count, *libc::__error())
        };
        errno == 0 && (count == 0 || (count == 1 && members[0] == self.child.id() as libc::pid_t))
    }
}
#[cfg(unix)]
impl Drop for OwnedChild {
    fn drop(&mut self) {
        use std::{
            thread,
            time::{Duration, Instant},
        };
        if !self.signal_allowed {
            return;
        }
        let _ = self.stop();
        let until = Instant::now() + Duration::from_secs(2);
        while Instant::now() < until {
            if !matches!(self.child.try_wait(), Ok(None)) {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
#[cfg(unix)]
#[derive(Default)]
struct CaptureReport {
    directory: std::path::PathBuf,
    stdout_bytes: usize,
    stderr_bytes: usize,
    cleanup_confirmed: bool,
    pipe_eof: bool,
}
#[cfg(unix)]
struct BoundedPipe<R> {
    reader: Option<R>,
    file: fs::File,
    count: usize,
    limit: usize,
    overflow: bool,
}
#[cfg(unix)]
impl<R: std::io::Read + std::os::fd::AsRawFd> BoundedPipe<R> {
    fn new(reader: R, file: fs::File, limit: usize) -> std::io::Result<Self> {
        let fd = reader.as_raw_fd();
        // SAFETY: descriptor belongs to reader and remains live during calls.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            reader: Some(reader),
            file,
            count: 0,
            limit,
            overflow: false,
        })
    }
    fn drain(&mut self) -> std::io::Result<bool> {
        use std::io::Write;
        let Some(reader) = self.reader.as_mut() else {
            return Ok(false);
        };
        let mut buffer = [0u8; 8192];
        // Finite bursts preserve checks/deadline fairness under stdout flood.
        for _ in 0..16 {
            let capacity = if self.overflow {
                buffer.len()
            } else {
                buffer.len().min(self.limit - self.count + 1)
            };
            match reader.read(&mut buffer[..capacity]) {
                Ok(0) => {
                    self.reader = None;
                    break;
                }
                Ok(count) => {
                    let keep = count.min(self.limit - self.count);
                    self.file.write_all(&buffer[..keep])?;
                    self.count += keep;
                    if keep < count {
                        self.overflow = true;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(self.overflow)
    }
    fn closed(&self) -> bool {
        self.reader.is_none()
    }
}
// Argv-only, hard bounded pipe reads and bounded private-file writes. Failed
// captures retained; process-group ownership is not escape containment.
#[cfg(unix)]
fn run_bounded(
    root: &Path,
    program: &str,
    args: &[&str],
    seconds: u64,
    limit: usize,
) -> Result<Vec<u8>> {
    run_bounded_report(root, program, args, seconds, limit, None)
}
#[cfg(unix)]
fn run_bounded_report(
    root: &Path,
    program: &str,
    args: &[&str],
    seconds: u64,
    limit: usize,
    mut report: Option<&mut CaptureReport>,
) -> Result<Vec<u8>> {
    use std::{
        os::unix::{
            fs::{DirBuilderExt, OpenOptionsExt},
            process::CommandExt,
        },
        process::Stdio,
        thread,
        time::{Duration, Instant},
    };
    require(
        (1..=60).contains(&seconds) && limit > 0 && limit <= MESSAGE_LIMIT,
        "process budget invalid",
    )?;
    struct Capture(std::path::PathBuf, bool);
    impl Drop for Capture {
        fn drop(&mut self) {
            if !self.1 {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
    }
    let mut admitted = None;
    for attempt in 0..100 {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "aegis-inventory-{}-{nonce}-{attempt}",
            std::process::id()
        ));
        let mut b = fs::DirBuilder::new();
        b.mode(0o700);
        match b.create(&path) {
            Ok(()) => {
                admitted = Some(Capture(path, true));
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.into()),
        }
    }
    let mut capture = admitted.ok_or("cannot create private process capture")?;
    if let Some(r) = report.as_deref_mut() {
        r.directory = capture.0.clone();
    }
    let output = capture.0.join("stdout");
    let errors = capture.0.join("stderr");
    let create = |p: &Path| {
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(p)
    };
    // Parent-owned files are never given to the child: only OS-bounded pipes.
    let out_file = create(&output)?;
    let err_file = create(&errors)?;
    let child = Command::new(program)
        .args(args)
        .current_dir(root)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut owner = OwnedChild {
        child,
        signal_allowed: true,
        signalled: false,
    };
    let mut stdout = BoundedPipe::new(
        owner.child.stdout.take().ok_or("stdout pipe absent")?,
        out_file,
        limit,
    )?;
    let mut stderr = BoundedPipe::new(
        owner.child.stderr.take().ok_or("stderr pipe absent")?,
        err_file,
        65536,
    )?;
    let deadline = Instant::now() + Duration::from_secs(seconds);
    let mut refusal = None;
    loop {
        let stdout_over = stdout.drain()?;
        let stderr_over = stderr.drain()?;
        if stdout_over || stderr_over {
            refusal = Some("process output exceeds bound");
            break;
        }
        match owner.observe_exit() {
            Ok(true) => break,
            Ok(false) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.raw_os_error() == Some(libc::ECHILD) => {
                return Err("process ownership lost; group signal refused".into())
            }
            Err(_) => {
                refusal = Some("process observation failed");
                break;
            }
        }
        if Instant::now() >= deadline {
            refusal = Some("process deadline exceeded");
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    if owner.stop().is_err() {
        refusal = Some("owned process-group cleanup failed");
    }
    let cleanup = Instant::now() + Duration::from_secs(2);
    let mut status = None;
    loop {
        let stdout_over = stdout.drain()?;
        let stderr_over = stderr.drain()?;
        if stdout_over || stderr_over {
            refusal = Some("process output exceeds bound");
        }
        if status.is_none() {
            if let Some(s) = owner.child.try_wait()? {
                owner.signal_allowed = false;
                status = Some(s);
            }
        }
        if status.is_some() && stdout.closed() && stderr.closed() {
            break;
        }
        if Instant::now() >= cleanup {
            refusal = Some("process cleanup/EOF deadline exceeded");
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    if let Some(r) = report {
        r.stdout_bytes = stdout.count;
        r.stderr_bytes = stderr.count;
        r.cleanup_confirmed = status.is_some();
        r.pipe_eof = stdout.closed() && stderr.closed();
    }
    if let Some(e) = refusal {
        return Err(e.into());
    }
    require(
        status.is_some_and(|s| s.success()),
        "bounded metadata command failed",
    )?;
    let bytes = bounded_regular(&output, limit)?;
    capture.1 = false;
    Ok(bytes)
}
#[cfg(not(unix))]
fn run_bounded(
    _root: &Path,
    _program: &str,
    _args: &[&str],
    _seconds: u64,
    _limit: usize,
) -> Result<Vec<u8>> {
    Err("Linux shipping inventory generation requires a Unix producer".into())
}

pub(crate) const BUILD_LEAF: &str = "client-build-record.json";
fn check_record(record: &BuildRecord, provenance: &Value, binary: &[u8]) -> Result<()> {
    let (revision, target, lock) = binding(provenance, binary)?;
    require(
        record.schema == "aegis_linux_client_build_record_v1"
            && record.source_revision == revision
            && record.target_triple == target
            && record.cargo_lock_sha256 == lock
            && record.binary_sha256 == digest(binary)
            && record.default_features
            && record.requested_features == features(provenance)?
            && record.target_evidence == "explicit_cargo_target_and_fixed_producer_invocation"
            && hex(&record.compiler_artifact_message_sha256, 64)
            && hex(&record.build_message_stream_sha256, 64)
            && record
                .resolved_root_features
                .windows(2)
                .all(|w| w[0] < w[1])
            && FEATURES
                .iter()
                .all(|f| record.resolved_root_features.iter().any(|x| x == f)),
        "inventory build record mismatch",
    )
}
fn prepare_build_record(
    root: &Path,
    messages: &Path,
    bundle: &Path,
    target: &str,
    revision: &str,
    host: &[u8],
    head: &[u8],
) -> Result<BuildRecord> {
    let pins = source_pins(root)?;
    let raw = bounded_regular(messages, MESSAGE_LIMIT)?;
    require(
        bounded_regular(&root.join("Cargo.lock"), LIMIT)?
            == bounded_regular(&bundle.join("Cargo.lock"), LIMIT)?,
        "producer root/staged lock mismatch",
    )?;
    require(
        std::str::from_utf8(host)?
            .lines()
            .any(|l| l == format!("host: {target}")),
        "native compiler target differs",
    )?;
    let mut artifacts = Vec::new();
    let mut finished = 0;
    for line in std::str::from_utf8(&raw)?.lines() {
        let v: Value = serde_json::from_str(line)?;
        if v["reason"] == "build-finished" {
            require(v["success"] == true, "client build failed")?;
            finished += 1;
        }
        if v["reason"] == "compiler-artifact"
            && v["target"]["name"] == "aegis-client"
            && v["target"]["kind"] == serde_json::json!(["bin"])
        {
            artifacts.push(v);
        }
    }
    require(
        finished == 1 && artifacts.len() == 1,
        "missing or duplicate client compiler artifact",
    )?;
    let a = &artifacts[0];

    let manifest = fs::canonicalize(text(a, "manifest_path")?)?;
    require(
        manifest == fs::canonicalize(root.join("aegis-client/Cargo.toml"))?,
        "compiler artifact package mismatch",
    )?;
    require(
        std::str::from_utf8(head)?.trim() == revision,
        "producer revision mismatch",
    )?;
    require(
        a["profile"]["test"] == false,
        "test executable cannot be shipped",
    )?;
    require(
        Path::new(text(a, "executable")?).ends_with(Path::new(target).join("release/aegis-client")),
        "compiler artifact target path differs",
    )?;
    let actual = bounded_regular(Path::new(text(a, "executable")?), BINARY_LIMIT)?;
    let binary = bounded_regular(&bundle.join("bin/aegis-client"), BINARY_LIMIT)?;
    require(
        actual == binary,
        "compiler artifact differs from staged client",
    )?;
    let mut resolved = BTreeSet::new();
    for feature in a["features"]
        .as_array()
        .ok_or("compiler features missing")?
    {
        require(
            resolved.insert(
                feature
                    .as_str()
                    .ok_or("compiler feature malformed")?
                    .to_string(),
            ),
            "compiler duplicate feature",
        )?;
    }
    let record = BuildRecord {
        schema: "aegis_linux_client_build_record_v1".into(),
        source_revision: revision.into(),
        target_triple: target.into(),
        cargo_lock_sha256: digest(&bounded_regular(&bundle.join("Cargo.lock"), LIMIT)?),
        binary_sha256: digest(&binary),
        default_features: true,
        requested_features: FEATURES.into_iter().map(str::to_owned).collect(),
        resolved_root_features: resolved.into_iter().collect(),
        compiler_artifact_message_sha256: digest(&serde_json::to_vec(a)?),
        build_message_stream_sha256: digest(&raw),
        target_evidence: "explicit_cargo_target_and_fixed_producer_invocation".into(),
    };
    let p = serde_json::json!({"git_sha":revision,"target_triple":target,"cargo_lock_sha256":record.cargo_lock_sha256,"binaries":{"aegis-client":{"sha256":record.binary_sha256,"features":FEATURES}}});
    check_record(&record, &p, &binary)?;

    verify_pins(&pins)?;
    require(
        bounded_regular(messages, MESSAGE_LIMIT)? == raw
            && bounded_regular(Path::new(text(a, "executable")?), BINARY_LIMIT)? == actual
            && bounded_regular(&bundle.join("bin/aegis-client"), BINARY_LIMIT)? == binary,
        "producer input changed during record preparation",
    )?;
    Ok(record)
}
pub(crate) fn write_build_record(
    messages: &Path,
    bundle: &Path,
    target: &str,
    revision: &str,
) -> Result<()> {
    let root = std::env::current_dir()?;
    let pins = source_pins(&root)?;
    let host = run_bounded(&root, "rustc", &["-vV"], 10, 65536)?;
    let head = run_bounded(&root, "git", &["rev-parse", "HEAD"], 10, 65536)?;
    let record = prepare_build_record(&root, messages, bundle, target, revision, &host, &head)?;
    verify_pins(&pins)?;
    let current = run_bounded(&root, "git", &["rev-parse", "HEAD"], 10, 65536)?;
    require(
        current == head,
        "producer revision changed during collection",
    )?;
    persist_record(bundle, &record)
}
fn persist_record(bundle: &Path, record: &BuildRecord) -> Result<()> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut out = options.open(bundle.join(BUILD_LEAF))?;
    out.write_all(&serde_json::to_vec_pretty(&record)?)?;
    out.sync_all()?;
    Ok(())
}

fn require(ok: bool, error: &'static str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(error.into())
    }
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn hex(value: &str, n: usize) -> bool {
    value.len() == n
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| "inventory metadata missing text".into())
}
fn features(provenance: &Value) -> Result<Vec<String>> {
    let values = provenance["binaries"]["aegis-client"]["features"]
        .as_array()
        .ok_or("inventory features missing")?;
    let got: Vec<String> = values
        .iter()
        .map(|v| {
            v.as_str()
                .map(str::to_owned)
                .ok_or("inventory feature invalid")
        })
        .collect::<std::result::Result<_, _>>()?;
    let set: BTreeSet<_> = got.iter().map(String::as_str).collect();
    require(
        got.len() == FEATURES.len() && set == FEATURES.into_iter().collect(),
        "inventory shipping feature mismatch",
    )?;
    Ok(FEATURES.into_iter().map(str::to_owned).collect())
}
fn binding(provenance: &Value, binary: &[u8]) -> Result<(String, String, String)> {
    let revision = text(provenance, "git_sha")?;
    let target = text(provenance, "target_triple")?;
    let lock = text(provenance, "cargo_lock_sha256")?;
    require(
        hex(revision, 40) && hex(lock, 64),
        "inventory source identity invalid",
    )?;
    require(
        matches!(
            target,
            "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
        ),
        "inventory unsupported target",
    )?;
    require(
        provenance["binaries"]["aegis-client"]["sha256"] == digest(binary),
        "inventory client digest mismatch",
    )?;
    features(provenance)?;
    Ok((revision.into(), target.into(), lock.into()))
}
fn safe_token(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 256
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
}
fn shape(v: &Inventory) -> Result<()> {
    require(
        v.schema == "aegis_shipping_client_cargo_inventory_v1"
            && v.scope == "selected_target_filtered_cargo_graph_not_compiler_linkage"
            && !v.native_payload_complete
            && !v.compiler_linkage_proven
            && v.default_features,
        "inventory scope/schema invalid",
    )?;
    require(
        hex(&v.cargo_metadata_sha256, 64) && !v.components.is_empty() && v.components.len() <= 4096,
        "inventory graph bounds invalid",
    )?;
    let mut by_key = BTreeMap::new();
    let mut edges = 0;
    for c in &v.components {
        require(
            safe_token(&c.name) && safe_token(&c.version) && hex(&c.source_identity_sha256, 64),
            "inventory component identity invalid",
        )?;
        require(
            matches!(
                c.source_kind.as_str(),
                "reviewed_local_manifest" | "crates_io_registry"
            ),
            "inventory component source invalid",
        )?;
        require(
            c.key == format!("{}@{}#{}", c.name, c.version, c.source_identity_sha256),
            "inventory component key invalid",
        )?;
        require(
            by_key.insert(c.key.clone(), c).is_none(),
            "inventory duplicate component",
        )?;
        require(
            c.features.windows(2).all(|w| w[0] < w[1]) && c.features.iter().all(|f| safe_token(f)),
            "inventory component features invalid",
        )?;
        require(
            c.dependencies.windows(2).all(|w| w[0] < w[1]),
            "inventory duplicate/unsorted edge",
        )?;
        edges += c.dependencies.len();
    }
    require(
        edges <= 16384 && v.components.windows(2).all(|w| w[0].key < w[1].key),
        "inventory graph order/bounds invalid",
    )?;
    let root = by_key
        .get(&v.root_component)
        .ok_or("inventory root absent")?;
    require(
        root.name == "aegis-client" && root.source_kind == "reviewed_local_manifest",
        "inventory root invalid",
    )?;
    require(
        FEATURES
            .iter()
            .all(|f| root.features.iter().any(|v| v == f)),
        "inventory resolved root feature omission",
    )?;
    let mut visited = BTreeSet::new();
    let mut pending = vec![v.root_component.as_str()];
    while let Some(key) = pending.pop() {
        if !visited.insert(key) {
            continue;
        }
        let c = by_key.get(key).ok_or("inventory dependency absent")?;
        pending.extend(c.dependencies.iter().map(String::as_str));
    }
    require(
        visited.len() == by_key.len(),
        "inventory unreachable component",
    )
}
fn render(
    meta: &Value,
    provenance: &Value,
    binary: &[u8],
    local: &BTreeMap<String, String>,
    producer: BuildRecord,
) -> Result<Vec<u8>> {
    let (revision, target, lock) = binding(provenance, binary)?;
    check_record(&producer, provenance, binary)?;
    let packages = meta["packages"]
        .as_array()
        .ok_or("inventory packages absent")?;
    let nodes = meta["resolve"]["nodes"]
        .as_array()
        .ok_or("inventory resolve graph absent")?;
    require(
        packages.len() <= 4096 && nodes.len() <= 4096,
        "inventory metadata too large",
    )?;
    let mut package_map = BTreeMap::new();
    for p in packages {
        require(
            package_map.insert(text(p, "id")?, p).is_none(),
            "inventory duplicate package id",
        )?;
    }
    let mut node_map = BTreeMap::new();
    for n in nodes {
        require(
            node_map.insert(text(n, "id")?, n).is_none(),
            "inventory duplicate node id",
        )?;
    }
    let roots: Vec<_> = packages
        .iter()
        .filter(|p| p["name"] == "aegis-client" && p["source"].is_null())
        .collect();
    require(roots.len() == 1, "inventory ambiguous client root")?;
    let root_id = text(roots[0], "id")?;
    let mut pending = vec![root_id];
    let mut selected = BTreeMap::new();
    while let Some(id) = pending.pop() {
        if selected.contains_key(id) {
            continue;
        }
        let n = node_map.get(id).ok_or("inventory node absent")?;
        let deps = n["deps"]
            .as_array()
            .ok_or("inventory dependency list absent")?;
        let mut keep = BTreeSet::new();
        for d in deps {
            let kinds = d["dep_kinds"]
                .as_array()
                .ok_or("inventory dependency kinds absent")?;
            require(!kinds.is_empty(), "inventory dependency kind empty")?;
            let mut retained = false;
            for k in kinds {
                require(
                    k["kind"].is_null() || matches!(k["kind"].as_str(), Some("build" | "dev")),
                    "inventory dependency kind unknown",
                )?;
                retained |= k["kind"] != "dev";
            }
            if retained {
                let dep = text(d, "pkg")?;
                keep.insert(dep);
                pending.push(dep);
            }
        }
        selected.insert(id, keep);
    }
    let mut keys = BTreeMap::new();
    for id in selected.keys() {
        let p = package_map.get(id).ok_or("inventory package absent")?;
        let source = if p["source"].is_null() {
            local
                .get(*id)
                .ok_or("inventory local provenance absent")?
                .clone()
        } else {
            require(
                p["source"] == "registry+https://github.com/rust-lang/crates.io-index",
                "inventory unreviewed registry/source",
            )?;
            digest(
                format!(
                    "{}:{}:{}",
                    text(p, "name")?,
                    text(p, "version")?,
                    text(p, "source")?
                )
                .as_bytes(),
            )
        };
        keys.insert(
            *id,
            format!("{}@{}#{}", text(p, "name")?, text(p, "version")?, source),
        );
    }
    let mut components = Vec::new();
    for (id, deps) in &selected {
        let p = package_map[id];
        let n = node_map[id];
        let resolved = n["features"]
            .as_array()
            .ok_or("inventory resolved features absent")?;
        let mut fs = BTreeSet::new();
        for f in resolved {
            require(
                fs.insert(f.as_str().ok_or("inventory feature invalid")?.to_string()),
                "inventory duplicate feature",
            )?;
        }
        let key = keys[id].clone();
        components.push(Component {
            source_identity_sha256: key
                .rsplit('#')
                .next()
                .ok_or("inventory key invalid")?
                .into(),
            key,
            name: text(p, "name")?.into(),
            version: text(p, "version")?.into(),
            source_kind: if p["source"].is_null() {
                "reviewed_local_manifest"
            } else {
                "crates_io_registry"
            }
            .into(),
            features: fs.into_iter().collect(),
            dependencies: deps
                .iter()
                .map(|d| {
                    keys.get(d)
                        .cloned()
                        .ok_or("inventory missing dependency key")
                })
                .collect::<std::result::Result<BTreeSet<_>, _>>()?
                .into_iter()
                .collect(),
        });
    }
    components.sort_by(|a, b| a.key.cmp(&b.key));
    let v = Inventory {
        schema: "aegis_shipping_client_cargo_inventory_v1".into(),
        scope: "selected_target_filtered_cargo_graph_not_compiler_linkage".into(),
        native_payload_complete: false,
        compiler_linkage_proven: false,
        source_revision: revision,
        target_triple: target,
        default_features: true,
        requested_features: features(provenance)?,
        cargo_lock_sha256: lock,
        client_binary_sha256: digest(binary),
        cargo_metadata_sha256: digest(&serde_json::to_vec(meta)?),
        producer,
        root_component: keys[root_id].clone(),
        components,
    };
    shape(&v)?;
    let root = v
        .components
        .iter()
        .find(|c| c.key == v.root_component)
        .ok_or("inventory root absent")?;
    require(
        root.features == v.producer.resolved_root_features,
        "inventory compiler/metadata root features differ",
    )?;
    Ok(serde_json::to_vec_pretty(&v)?)
}
pub(crate) fn validate(bytes: &[u8], provenance: &Value, binary: &[u8]) -> Result<()> {
    require(bytes.len() <= LIMIT, "inventory payload too large")?;
    let v: Inventory = serde_json::from_slice(bytes)?;
    shape(&v)?;
    check_record(&v.producer, provenance, binary)?;
    let root = v
        .components
        .iter()
        .find(|c| c.key == v.root_component)
        .ok_or("inventory root absent")?;
    require(
        root.features == v.producer.resolved_root_features,
        "inventory compiler/metadata root features differ",
    )?;
    let (revision, target, lock) = binding(provenance, binary)?;
    require(
        v.source_revision == revision
            && v.target_triple == target
            && v.cargo_lock_sha256 == lock
            && v.client_binary_sha256 == digest(binary)
            && v.requested_features == features(provenance)?,
        "inventory provenance mismatch",
    )
}
pub(crate) fn generate(
    root: &Path,
    operator: &Path,
    provenance: &Value,
    binary: &[u8],
) -> Result<Vec<u8>> {
    let (revision, target, lock) = binding(provenance, binary)?;
    let canonical = fs::canonicalize(root)?;
    let initial = source_pins(root)?;
    let head = run_bounded(root, "git", &["rev-parse", "HEAD"], 10, 65536)?;
    require(
        std::str::from_utf8(&head)?.trim() == revision,
        "inventory checkout revision mismatch",
    )?;
    let lock_bytes = bounded_regular(&root.join("Cargo.lock"), LIMIT)?;
    require(digest(&lock_bytes) == lock, "inventory lock mismatch")?;
    let output = run_bounded(
        root,
        "cargo",
        &[
            "metadata",
            "--locked",
            "--offline",
            "--format-version=1",
            "--filter-platform",
            &target,
            "--features",
            "aegis-client/raw-socket,aegis-client/chrome-like-tls,aegis-client/chrome-like-quic",
        ],
        60,
        MESSAGE_LIMIT,
    )?;
    let meta: Value = serde_json::from_slice(&output)?;
    require(
        fs::canonicalize(text(&meta, "workspace_root")?)? == canonical,
        "inventory metadata workspace mismatch",
    )?;
    let mut local = BTreeMap::new();
    let mut pins = BTreeMap::new();
    for p in meta["packages"]
        .as_array()
        .ok_or("inventory packages absent")?
    {
        if !p["source"].is_null() {
            continue;
        }
        let path = fs::canonicalize(text(p, "manifest_path")?)?;
        require(
            path.starts_with(&canonical),
            "inventory local package escapes reviewed checkout",
        )?;
        let bytes = bounded_regular(&path, 512 * 1024)?;
        require(
            bytes.len() <= 512 * 1024,
            "inventory local manifest too large",
        )?;
        let h = digest(&bytes);
        local.insert(text(p, "id")?.into(), h.clone());
        pins.insert(path, h);
    }
    let record_raw = bounded_regular(&operator.join(BUILD_LEAF), 65536)?;
    require(record_raw.len() <= 65536, "build record too large")?;
    let producer: BuildRecord = serde_json::from_slice(&record_raw)?;
    let bytes = render(&meta, provenance, binary, &local, producer)?;
    require(
        bounded_regular(&root.join("Cargo.lock"), LIMIT)? == lock_bytes,
        "inventory lock changed during collection",
    )?;
    for (path, h) in pins {
        require(
            digest(&bounded_regular(&path, 512 * 1024)?) == h,
            "inventory manifest changed during collection",
        )?;
    }
    verify_pins(&initial)?;
    let current = run_bounded(root, "git", &["rev-parse", "HEAD"], 10, 65536)?;
    require(
        current == head,
        "inventory revision changed during collection",
    )?;
    validate(&bytes, provenance, binary)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn producer(p: &Value) -> BuildRecord {
        BuildRecord {
            schema: "aegis_linux_client_build_record_v1".into(),
            source_revision: p["git_sha"].as_str().unwrap().into(),
            target_triple: p["target_triple"].as_str().unwrap().into(),
            cargo_lock_sha256: p["cargo_lock_sha256"].as_str().unwrap().into(),
            binary_sha256: digest(b"binary"),
            default_features: true,
            requested_features: FEATURES.into_iter().map(str::to_owned).collect(),
            resolved_root_features: FEATURES.into_iter().map(str::to_owned).collect(),
            compiler_artifact_message_sha256: "d".repeat(64),
            build_message_stream_sha256: "e".repeat(64),
            target_evidence: "explicit_cargo_target_and_fixed_producer_invocation".into(),
        }
    }
    fn fixture() -> (Value, Value, BTreeMap<String, String>) {
        let p = json!({"git_sha":"a".repeat(40),"target_triple":"x86_64-unknown-linux-gnu","cargo_lock_sha256":"b".repeat(64),"binaries":{"aegis-client":{"sha256":digest(b"binary"),"features":["raw-socket","chrome-like-tls","chrome-like-quic"]}}});
        let m = json!({"packages":[{"id":"root","name":"aegis-client","version":"1.0.0","source":null},{"id":"dep","name":"dep","version":"1.0.0","source":"registry+https://github.com/rust-lang/crates.io-index"}],"resolve":{"nodes":[{"id":"root","features":FEATURES,"deps":[{"pkg":"dep","dep_kinds":[{"kind":null}]}]},{"id":"dep","features":[],"deps":[]}]}});
        (m, p, BTreeMap::from([("root".into(), "c".repeat(64))]))
    }
    #[test]
    fn selected_graph_roundtrip_and_exact_bindings() {
        let (m, p, l) = fixture();
        let bytes = render(&m, &p, b"binary", &l, producer(&p)).unwrap();
        validate(&bytes, &p, b"binary").unwrap();
        for key in ["git_sha", "target_triple", "cargo_lock_sha256"] {
            let mut bad = p.clone();
            bad[key] = json!("wrong");
            assert!(validate(&bytes, &bad, b"binary").is_err());
        }
        assert!(validate(&bytes, &p, b"other").is_err());
        let mut bad = p.clone();
        bad["binaries"]["aegis-client"]["features"] = json!(["raw-socket"]);
        assert!(validate(&bytes, &bad, b"binary").is_err());
    }
    #[test]
    fn absent_duplicate_and_unknown_graph_fail_closed() {
        let (m, p, l) = fixture();
        let mut bad = m.clone();
        bad["resolve"]["nodes"].as_array_mut().unwrap().pop();
        assert!(render(&bad, &p, b"binary", &l, producer(&p)).is_err());
        let mut bad = m.clone();
        bad["packages"]
            .as_array_mut()
            .unwrap()
            .push(m["packages"][0].clone());
        assert!(render(&bad, &p, b"binary", &l, producer(&p)).is_err());
        let mut bad = m.clone();
        bad["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["kind"] = json!("unknown");
        assert!(render(&bad, &p, b"binary", &l, producer(&p)).is_err());
        assert!(render(&m, &p, b"binary", &BTreeMap::new(), producer(&p)).is_err());
    }
    #[test]
    fn closed_inventory_rejects_component_omission_and_overclaim() {
        let (m, p, l) = fixture();
        let bytes = render(&m, &p, b"binary", &l, producer(&p)).unwrap();
        let base: Value = serde_json::from_slice(&bytes).unwrap();
        for field in ["native_payload_complete", "compiler_linkage_proven"] {
            let mut bad = base.clone();
            bad[field] = json!(true);
            assert!(validate(&serde_json::to_vec(&bad).unwrap(), &p, b"binary").is_err());
        }
        let mut bad = base.clone();
        bad["extra"] = json!(true);
        assert!(validate(&serde_json::to_vec(&bad).unwrap(), &p, b"binary").is_err());
        let mut bad = base;
        bad["components"]
            .as_array_mut()
            .unwrap()
            .retain(|c| c["name"] == "aegis-client");
        assert!(validate(&serde_json::to_vec(&bad).unwrap(), &p, b"binary").is_err());
    }
    #[test]
    fn dev_only_edge_excluded_without_losing_build_edge() {
        let (mut m, p, l) = fixture();
        m["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["kind"] = json!("dev");
        let bytes = render(&m, &p, b"binary", &l, producer(&p)).unwrap();
        let v: Inventory = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v.components.len(), 1);
        m["resolve"]["nodes"][0]["deps"][0]["dep_kinds"][0]["kind"] = json!("build");
        let bytes = render(&m, &p, b"binary", &l, producer(&p)).unwrap();
        let v: Inventory = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(v.components.len(), 2);
    }
    fn actual_paths() -> (
        tempfile::TempDir,
        std::path::PathBuf,
        std::path::PathBuf,
        std::path::PathBuf,
        Value,
    ) {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("root");
        let bundle = temp.path().join("bundle");
        fs::create_dir_all(root.join("aegis-client")).unwrap();
        fs::create_dir_all(bundle.join("bin")).unwrap();
        fs::write(root.join("Cargo.toml"), b"workspace fixture").unwrap();
        fs::write(
            root.join("aegis-client/Cargo.toml"),
            b"client manifest fixture",
        )
        .unwrap();
        for path in [root.join("Cargo.lock"), bundle.join("Cargo.lock")] {
            fs::write(path, b"locked fixture").unwrap();
        }
        let executable = temp
            .path()
            .join("x86_64-unknown-linux-gnu/release/aegis-client");
        fs::create_dir_all(executable.parent().unwrap()).unwrap();
        fs::write(&executable, b"binary").unwrap();
        fs::write(bundle.join("bin/aegis-client"), b"binary").unwrap();
        let artifact = json!({"reason":"compiler-artifact","target":{"name":"aegis-client","kind":["bin"]},"profile":{"test":false},"manifest_path":root.join("aegis-client/Cargo.toml"),"executable":executable,"features":FEATURES});
        let messages = temp.path().join("messages.jsonl");
        fs::write(
            &messages,
            format!(
                "{}\n{}\n",
                artifact,
                json!({"reason":"build-finished","success":true})
            ),
        )
        .unwrap();
        (temp, root, bundle, messages, artifact)
    }
    fn prepare_fixture(root: &Path, bundle: &Path, messages: &Path) -> Result<BuildRecord> {
        prepare_build_record(
            root,
            messages,
            bundle,
            "x86_64-unknown-linux-gnu",
            &"a".repeat(40),
            b"host: x86_64-unknown-linux-gnu\n",
            format!("{}\n", "a".repeat(40)).as_bytes(),
        )
    }
    #[test]
    fn producer_actual_path_inputs_persist_create_new_and_scope() {
        let (_t, root, bundle, messages, _) = actual_paths();
        let record = prepare_fixture(&root, &bundle, &messages).unwrap();
        assert_eq!(record.binary_sha256, digest(b"binary"));
        assert_eq!(record.cargo_lock_sha256, digest(b"locked fixture"));
        persist_record(&bundle, &record).unwrap();
        let saved = bounded_regular(&bundle.join(BUILD_LEAF), 65536).unwrap();
        let parsed: BuildRecord = serde_json::from_slice(&saved).unwrap();
        assert_eq!(parsed, record);
        assert!(persist_record(&bundle, &record).is_err());
        assert_eq!(
            bounded_regular(&bundle.join(BUILD_LEAF), 65536).unwrap(),
            saved
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(bundle.join(BUILD_LEAF))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    #[test]
    fn producer_replaced_executable_staged_lock_and_test_artifact_refuse() {
        for scenario in 0..5 {
            let (_t, root, bundle, messages, mut artifact) = actual_paths();
            match scenario {
                0 => fs::write(artifact["executable"].as_str().unwrap(), b"replaced").unwrap(),
                1 => fs::write(bundle.join("bin/aegis-client"), b"replaced").unwrap(),
                2 => fs::write(bundle.join("Cargo.lock"), b"changed-lock").unwrap(),
                3 => {
                    artifact["profile"]["test"] = json!(true);
                    fs::write(
                        &messages,
                        format!(
                            "{}\n{}\n",
                            artifact,
                            json!({"reason":"build-finished","success":true})
                        ),
                    )
                    .unwrap();
                }
                _ => {
                    artifact["features"] = json!(["raw-socket"]);
                    fs::write(
                        &messages,
                        format!(
                            "{}\n{}\n",
                            artifact,
                            json!({"reason":"build-finished","success":true})
                        ),
                    )
                    .unwrap();
                }
            }
            assert!(prepare_fixture(&root, &bundle, &messages).is_err());
            assert!(!bundle.join(BUILD_LEAF).exists());
        }
    }
    #[test]
    fn producer_missing_duplicate_root_or_failed_build_refuse() {
        for scenario in 0..4 {
            let (_t, root, bundle, messages, artifact) = actual_paths();
            let lines = match scenario {
                0 => format!("{}\n", json!({"reason":"build-finished","success":true})),
                1 => format!(
                    "{artifact}\n{artifact}\n{}\n",
                    json!({"reason":"build-finished","success":true})
                ),
                2 => format!("{artifact}\n"),
                _ => format!(
                    "{artifact}\n{}\n",
                    json!({"reason":"build-finished","success":false})
                ),
            };
            fs::write(&messages, lines).unwrap();
            assert!(prepare_fixture(&root, &bundle, &messages).is_err());
            assert!(!bundle.join(BUILD_LEAF).exists());
        }
    }
    #[test]
    fn bounded_path_reads_reject_sparse_oversize_nonregular_and_symlink() {
        let t = tempfile::tempdir().unwrap();
        let large = t.path().join("large");
        fs::File::create(&large)
            .unwrap()
            .set_len(MESSAGE_LIMIT as u64 + 1)
            .unwrap();
        assert!(bounded_regular(&large, MESSAGE_LIMIT).is_err());
        assert!(bounded_regular(t.path(), 1024).is_err());
        #[cfg(unix)]
        {
            let link = t.path().join("link");
            std::os::unix::fs::symlink(&large, &link).unwrap();
            assert!(bounded_regular(&link, MESSAGE_LIMIT + 1).is_err());
        }
        let (_t, root, bundle, messages, _) = actual_paths();
        fs::File::create(&messages)
            .unwrap()
            .set_len(MESSAGE_LIMIT as u64 + 1)
            .unwrap();
        assert!(prepare_fixture(&root, &bundle, &messages).is_err());
    }
    #[test]
    fn source_pin_recheck_detects_changed_manifest_and_lock() {
        for leaf in ["Cargo.lock", "aegis-client/Cargo.toml"] {
            let (_t, root, _, _, _) = actual_paths();
            let pins = source_pins(&root).unwrap();
            verify_pins(&pins).unwrap();
            fs::write(root.join(leaf), b"changed").unwrap();
            assert!(verify_pins(&pins).is_err());
        }
    }

    #[test]
    fn dependency_mapping_sorts_component_keys_not_package_ids() {
        let (mut m, p, mut local) = fixture();
        m["packages"][1]["id"] = json!("a-registry");
        m["packages"][1]["name"] = json!("z-registry");
        m["resolve"]["nodes"][1]["id"] = json!("a-registry");
        m["packages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"z-local","name":"a-local","version":"1.0.0","source":null}));
        m["resolve"]["nodes"]
            .as_array_mut()
            .unwrap()
            .push(json!({"id":"z-local","features":[],"deps":[]}));
        m["resolve"]["nodes"][0]["deps"] = json!([{"pkg":"a-registry","dep_kinds":[{"kind":null}]},{"pkg":"z-local","dep_kinds":[{"kind":"build"}]}]);
        local.insert("z-local".into(), "f".repeat(64));
        let bytes = render(&m, &p, b"binary", &local, producer(&p)).unwrap();
        let inventory: Inventory = serde_json::from_slice(&bytes).unwrap();
        let root = inventory
            .components
            .iter()
            .find(|c| c.name == "aegis-client")
            .unwrap();
        assert!(root.dependencies[0].starts_with("a-local@"));
        assert!(root.dependencies[1].starts_with("z-registry@"));
        validate(&bytes, &p, b"binary").unwrap();
    }
    #[cfg(unix)]
    #[test]
    fn bounded_runner_normal_argv_output_and_eof_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let mut report = CaptureReport::default();
        let bytes = run_bounded_report(
            temp.path(),
            "/usr/bin/printf",
            &["%s", "literal $(never_execute)"],
            2,
            1024,
            Some(&mut report),
        )
        .unwrap();
        assert_eq!(bytes, b"literal $(never_execute)");
        assert!(report.cleanup_confirmed && report.pipe_eof);
        assert_eq!(report.stdout_bytes, bytes.len());
        assert_eq!(report.stderr_bytes, 0);
    }
    #[cfg(unix)]
    #[test]
    fn bounded_runner_timeout_has_owned_cleanup_and_finite_capture() {
        let temp = tempfile::tempdir().unwrap();
        let mut report = CaptureReport::default();
        let started = std::time::Instant::now();
        let result = run_bounded_report(
            temp.path(),
            "/bin/sleep",
            &["5"],
            1,
            1024,
            Some(&mut report),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < std::time::Duration::from_secs(4));
        assert!(report.cleanup_confirmed && report.pipe_eof);
        assert!(report.stdout_bytes <= 1024 && report.stderr_bytes <= 65536);
        assert!(fs::metadata(report.directory.join("stdout")).unwrap().len() <= 1024);
    }
    #[cfg(unix)]
    #[test]
    fn bounded_runner_flood_cannot_write_beyond_hard_capture_limits() {
        let temp = tempfile::tempdir().unwrap();
        let mut report = CaptureReport::default();
        let result = run_bounded_report(
            temp.path(),
            "/usr/bin/yes",
            &["flood"],
            2,
            1024,
            Some(&mut report),
        );
        assert!(result.is_err());
        assert!(report.cleanup_confirmed && report.pipe_eof);
        assert_eq!(report.stdout_bytes, 1024);
        assert_eq!(
            fs::metadata(report.directory.join("stdout")).unwrap().len(),
            1024
        );
        let mut stderr = CaptureReport::default();
        let result = run_bounded_report(
            temp.path(),
            "/bin/sh",
            &["-c", "while :; do printf x >&2; done"],
            2,
            1024,
            Some(&mut stderr),
        );
        assert!(result.is_err());
        assert!(stderr.cleanup_confirmed && stderr.pipe_eof);
        assert_eq!(stderr.stderr_bytes, 65536);
        assert_eq!(
            fs::metadata(stderr.directory.join("stderr")).unwrap().len(),
            65536
        );
    }
    #[cfg(unix)]
    #[test]
    fn lost_reaped_child_identity_refuses_group_signal() {
        use std::{os::unix::process::CommandExt, process::Stdio};
        let child = Command::new("/usr/bin/printf")
            .arg("done")
            .process_group(0)
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let mut owner = OwnedChild {
            child,
            signal_allowed: true,
            signalled: false,
        };
        let pid = owner.child.id();
        let mut status = 0;
        // SAFETY: test deliberately reaps only this exact directly owned child to
        // model an external reaper, then verifies no group signal is admitted.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let result = unsafe { libc::waitpid(pid as libc::pid_t, &mut status, libc::WNOHANG) };
            if result == pid as libc::pid_t {
                break;
            }
            assert_eq!(result, 0);
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(
            owner.observe_exit().unwrap_err().raw_os_error(),
            Some(libc::ECHILD)
        );
        assert!(!owner.signal_allowed);
        owner.stop().unwrap();
        assert!(!owner.signalled);
    }
    #[test]
    fn producer_requires_explicit_target_artifact_path() {
        let (_t, root, bundle, messages, mut artifact) = actual_paths();
        let wrong = root.join("wrong-client");
        fs::write(&wrong, b"binary").unwrap();
        artifact["executable"] = json!(wrong);
        fs::write(
            &messages,
            format!(
                "{}\n{}\n",
                artifact,
                json!({"reason":"build-finished","success":true})
            ),
        )
        .unwrap();
        assert!(prepare_fixture(&root, &bundle, &messages).is_err());
    }
}
