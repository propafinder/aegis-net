//! Source-backed fixed systemd unit namespace, private staged capability producer.
//! Only the explicit systemd 255/259 profiles are admitted. Aliases, shadowed drop-ins,
//! unsafe links and unknown lookup roots refuse rather than inventing coverage.
use crate::profile_auto_stopped_service::{
    manager_query, InheritedInstallReadLock, InstallLock, ManagerQuery,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::CString,
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    path::{Component, Path, PathBuf},
};
pub(crate) type Result<T> = std::result::Result<T, &'static str>;
const REFUSED: &str = "Administrative AUTO unit namespace admission refused";
const UNIT: &str = "aegis-client.service";
const DROPINS: [&str; 3] = ["service.d", "aegis-.service.d", "aegis-client.service.d"];
const FILE_LIMIT: usize = 262144;
const TOTAL_LIMIT: usize = 4194304;
const RECORD_LIMIT: usize = 2048;
fn err<T>(_: T) -> &'static str {
    REFUSED
}
fn need(v: bool) -> Result<()> {
    if v {
        Ok(())
    } else {
        Err(REFUSED)
    }
}
fn c(v: &str) -> Result<CString> {
    CString::new(v).map_err(err)
}
fn fd(v: i32) -> Result<OwnedFd> {
    if v < 0 {
        Err(REFUSED)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(v) })
    }
}
fn stat(f: &OwnedFd) -> Result<libc::stat> {
    let mut m = std::mem::MaybeUninit::uninit();
    need(unsafe { libc::fstat(f.as_raw_fd(), m.as_mut_ptr()) } == 0)?;
    Ok(unsafe { m.assume_init() })
}
fn digest(v: &[u8]) -> String {
    hex::encode(Sha256::digest(v))
}
fn normal(path: &Path) -> bool {
    path.is_absolute()
        && path != Path::new("/")
        && path
            .components()
            .all(|x| matches!(x, Component::RootDir | Component::Normal(_)))
        && path.components().collect::<PathBuf>() == path
}
fn allowed_root(path: &Path) -> bool {
    normal(path)
        && [
            "/etc/systemd",
            "/run/systemd",
            "/usr/lib/systemd",
            "/usr/local/lib/systemd",
        ]
        .iter()
        .any(|p| path.starts_with(p) && path != Path::new(p))
}
fn properties(bytes: &[u8], keys: &[&str]) -> Result<BTreeMap<String, String>> {
    need(bytes.len() <= 8192)?;
    need(!bytes.iter().any(|b| b.is_ascii_control() && *b != b'\n'))?;
    let mut result = BTreeMap::new();
    for line in std::str::from_utf8(bytes).map_err(err)?.lines() {
        let (k, v) = line.split_once('=').ok_or(REFUSED)?;
        need(keys.contains(&k) && result.insert(k.into(), v.into()).is_none())?;
    }
    need(result.len() == keys.len())?;
    Ok(result)
}
/// Both fixed and transient namespace admission use the same closed version
/// set. This is no substitute for the native PID1/job and installed gates.
pub(super) fn admitted_manager_version(version: &str) -> bool {
    version.len() <= 256
        && version.is_ascii()
        && !version.chars().any(char::is_control)
        && matches!(
            version.split(|c: char| !c.is_ascii_digit()).next(),
            Some("255" | "259")
        )
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Manager {
    version: String,
    paths: Vec<PathBuf>,
    unit: BTreeMap<String, String>,
}
fn manager_from(path_bytes: &[u8], unit_bytes: &[u8]) -> Result<Manager> {
    let p = properties(path_bytes, &["Version", "UnitPath"])?;
    need(admitted_manager_version(&p["Version"]))?;
    let paths: Vec<_> = p["UnitPath"]
        .split_whitespace()
        .map(PathBuf::from)
        .collect();
    need(
        !paths.is_empty()
            && paths.len() <= 32
            && paths.iter().all(|p| allowed_root(p))
            && paths.iter().collect::<BTreeSet<_>>().len() == paths.len(),
    )?;
    let unit = properties(
        unit_bytes,
        &["Id", "LoadState", "FragmentPath", "DropInPaths", "Names"],
    )?;
    need(unit["Id"] == UNIT)?;
    need(unit["Names"] == UNIT)?;
    need(matches!(unit["LoadState"].as_str(), "loaded" | "not-found"))?;
    for value in [&unit["FragmentPath"], &unit["DropInPaths"]] {
        need(value.len() <= 8192 && !value.chars().any(char::is_control))?;
    }
    Ok(Manager {
        version: p["Version"].clone(),
        paths,
        unit,
    })
}
fn observe_manager() -> Result<Manager> {
    let paths = manager_query(ManagerQuery::SearchPaths)?;
    let unit = manager_query(ManagerQuery::UnitNamespace)?;
    manager_from(&paths, &unit)
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Metadata {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: i64,
    mtime_sec: i64,
    mtime_nsec: i64,
    ctime_sec: i64,
    ctime_nsec: i64,
}
fn metadata(m: &libc::stat, regular: bool) -> Metadata {
    // Linux nlink_t is u32 on ARM64 and u64 on x86_64; serde remains lossless.
    #[allow(clippy::useless_conversion)]
    let links = u64::from(m.st_nlink);
    Metadata {
        device: m.st_dev,
        inode: m.st_ino,
        uid: m.st_uid,
        gid: m.st_gid,
        mode: m.st_mode,
        links: if regular { links } else { 0 },
        size: if regular { m.st_size } else { 0 },
        mtime_sec: if regular { m.st_mtime } else { 0 },
        mtime_nsec: if regular { m.st_mtime_nsec } else { 0 },
        ctime_sec: if regular { m.st_ctime } else { 0 },
        ctime_nsec: if regular { m.st_ctime_nsec } else { 0 },
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Node {
    path: PathBuf,
    parent: PathBuf,
    name: String,
    kind: String,
    metadata: Option<Metadata>,
    sha256: Option<String>,
}
/// Opaque serde record: only producer capture mints an admitted source record.
/// Serialized bytes MUST be sealed by protected StageGuard/Header.leaves.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NamespaceRecord {
    schema: u32,
    manager: Manager,
    nodes: Vec<Node>,
    generation: String,
}
impl NamespaceRecord {
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }
    pub(crate) fn check_generation(&self) -> Result<()> {
        self.validate()
    }
    pub(crate) fn is_absent(&self) -> bool {
        self.manager.unit["LoadState"] == "not-found"
    }
    pub(crate) fn fixed_unit(&self) -> &str {
        UNIT
    }
    pub(crate) fn verify_original_singleton(
        &self,
        witness: &crate::profile_auto_unit_policy::linux::OriginalNamespaceWitness,
    ) -> Result<ManagedRole> {
        use crate::profile_auto_unit_policy::linux as policy;
        self.validate()?;
        let role = match witness.role {
            policy::LeafRole::BaseUnit => ManagedRole::BaseUnit,
            policy::LeafRole::Environment => ManagedRole::Environment,
        };
        let node = self
            .nodes
            .iter()
            .find(|n| n.path == role.fixed_path())
            .ok_or(REFUSED)?;
        match (&witness.metadata, witness.sha256) {
            (None, None) => need(
                node.kind == "missing-file" && node.metadata.is_none() && node.sha256.is_none(),
            )?,
            (Some(m), Some(hash)) => need(
                node.kind == "regular"
                    && node.metadata.as_ref() == Some(&witness_metadata(m))
                    && node.sha256.as_deref() == Some(hex::encode(hash).as_str()),
            )?,
            _ => return Err(REFUSED),
        }
        Ok(role)
    }
    fn seal(manager: Manager, nodes: Vec<Node>) -> Result<Self> {
        let bytes = serde_json::to_vec(&(&manager, &nodes)).map_err(err)?;
        Ok(Self {
            schema: 1,
            manager,
            nodes,
            generation: digest(&bytes),
        })
    }
    fn validate(&self) -> Result<()> {
        need(self.schema == 1 && self.nodes.len() <= RECORD_LIMIT)?;
        need(Self::seal(self.manager.clone(), self.nodes.clone())?.generation == self.generation)
    }
}
struct Held {
    path: PathBuf,
    file: OwnedFd,
    metadata: Metadata,
}
pub(crate) struct UnitNamespaceSnapshot {
    record: NamespaceRecord,
    held: Vec<Held>,
}
struct Capture {
    nodes: BTreeMap<PathBuf, Node>,
    held: Vec<Held>,
    total: usize,
}
impl Capture {
    fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
            held: Vec::new(),
            total: 0,
        }
    }
    fn remember(
        &mut self,
        path: &Path,
        file: &OwnedFd,
        m: libc::stat,
        regular: bool,
    ) -> Result<()> {
        let value = metadata(&m, regular);
        let path = path.to_path_buf();
        let node = Node {
            parent: path.parent().unwrap_or(Path::new("/")).into(),
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            path: path.clone(),
            kind: if regular { "regular" } else { "directory" }.into(),
            metadata: Some(value.clone()),
            sha256: None,
        };
        if let Some(prior) = self.nodes.get(&path) {
            need(prior.metadata == node.metadata && prior.kind == node.kind)?;
        } else {
            need(self.nodes.len() < RECORD_LIMIT)?;
            self.nodes.insert(path.clone(), node);
            self.held.push(Held {
                path,
                file: file.try_clone().map_err(err)?,
                metadata: value,
            });
        }
        Ok(())
    }
    /// Every absent component is witnessed beneath its held trusted parent.
    fn directory(&mut self, path: &Path) -> Result<Option<OwnedFd>> {
        need(path == Path::new("/") || normal(path))?;
        let mut current = fd(unsafe {
            libc::open(
                c("/")?.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        let mut at = PathBuf::from("/");
        let m = stat(&current)?;
        need(m.st_uid == 0 && m.st_mode & 0o022 == 0)?;
        self.remember(&at, &current, m, false)?;
        for component in path.components() {
            let Component::Normal(name) = component else {
                continue;
            };
            let name = name.to_str().ok_or(REFUSED)?;
            let next = at.join(name);
            let raw = unsafe {
                libc::openat(
                    current.as_raw_fd(),
                    c(name)?.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                need(std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))?;
                self.nodes.insert(
                    next.clone(),
                    Node {
                        path: next,
                        parent: at,
                        name: name.into(),
                        kind: "missing-directory".into(),
                        metadata: None,
                        sha256: None,
                    },
                );
                need(self.nodes.len() <= RECORD_LIMIT)?;
                return Ok(None);
            }
            let file = fd(raw)?;
            let m = stat(&file)?;
            need(m.st_uid == 0 && m.st_mode & 0o022 == 0)?;
            self.remember(&next, &file, m, false)?;
            current = file;
            at = next;
        }
        Ok(Some(current))
    }
    fn regular(&mut self, parent: &OwnedFd, path: &Path) -> Result<bool> {
        let name = path.file_name().and_then(|v| v.to_str()).ok_or(REFUSED)?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c(name)?.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            need(std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))?;
            self.nodes.insert(
                path.into(),
                Node {
                    path: path.into(),
                    parent: path.parent().ok_or(REFUSED)?.into(),
                    name: name.into(),
                    kind: "missing-file".into(),
                    metadata: None,
                    sha256: None,
                },
            );
            need(self.nodes.len() <= RECORD_LIMIT)?;
            return Ok(false);
        }
        let file = fd(raw)?;
        let m = stat(&file)?;
        need(
            m.st_uid == 0
                && m.st_mode & 0o022 == 0
                && m.st_mode & libc::S_IFMT == libc::S_IFREG
                && m.st_nlink == 1
                && m.st_size >= 0
                && m.st_size <= FILE_LIMIT as i64,
        )?;
        self.remember(path, &file, m, true)?;
        let mut bytes = zeroize::Zeroizing::new(Vec::new());
        File::from(file.try_clone().map_err(err)?)
            .take((FILE_LIMIT + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(err)?;
        need(
            bytes.len() == m.st_size as usize
                && metadata(&stat(&file)?, true) == metadata(&m, true),
        )?;
        self.total = self.total.checked_add(bytes.len()).ok_or(REFUSED)?;
        need(self.total <= TOTAL_LIMIT)?;
        self.nodes.get_mut(path).ok_or(REFUSED)?.sha256 = Some(digest(&bytes));
        Ok(true)
    }
    fn dropins(&mut self, root: &Path, name: &str) -> Result<Vec<PathBuf>> {
        let path = root.join(name);
        let Some(directory) = self.directory(&path)? else {
            return Ok(Vec::new());
        };
        let mut names = Vec::new();
        let listing_before = stat(&directory)?;
        for entry in
            std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd())).map_err(err)?
        {
            need(names.len() < 256)?;
            let entry = entry.map_err(err)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or(REFUSED)?;
            need(
                !name.is_empty()
                    && name.len() <= 255
                    && !name.chars().any(char::is_control)
                    && !name.contains('/')
                    && name != "."
                    && name != "..",
            )?;
            names.push(name.to_owned());
        }
        names.sort();
        need(names.windows(2).all(|w| w[0] != w[1]))?;
        let mut applicable = Vec::new();
        for name in names {
            let file = path.join(&name);
            need(self.regular(&directory, &file)?)?;
            if name.ends_with(".conf") {
                applicable.push(file)
            }
        }
        let listing_after = stat(&directory)?;
        need(
            listing_before.st_mtime == listing_after.st_mtime
                && listing_before.st_mtime_nsec == listing_after.st_mtime_nsec
                && listing_before.st_ctime == listing_after.st_ctime
                && listing_before.st_ctime_nsec == listing_after.st_ctime_nsec,
        )?;
        Ok(applicable)
    }
}
fn validate_effective(
    manager: &Manager,
    unit_files: &[PathBuf],
    dropins: &[PathBuf],
) -> Result<()> {
    if manager.unit["LoadState"] == "not-found" {
        need(
            unit_files.is_empty()
                && dropins.is_empty()
                && manager.unit["FragmentPath"].is_empty()
                && manager.unit["DropInPaths"].is_empty(),
        )?;
    } else {
        need(unit_files.first().is_some_and(|p| {
            p.as_os_str() == std::ffi::OsStr::new(&manager.unit["FragmentPath"])
        }))?;
        let expected: BTreeSet<_> = dropins.iter().collect();
        let actual: Vec<_> = manager.unit["DropInPaths"]
            .split_whitespace()
            .map(PathBuf::from)
            .collect();
        need(actual.len() == expected.len() && actual.iter().collect::<BTreeSet<_>>() == expected)?;
        // Conflicting same-name files require systemd precedence semantics not
        // implemented here; explicitly refuse that unsupported namespace.
        let names: BTreeSet<_> = dropins.iter().filter_map(|p| p.file_name()).collect();
        need(names.len() == dropins.len())?;
    }
    Ok(())
}
fn scan(manager: &Manager) -> Result<(Capture, Vec<PathBuf>, Vec<PathBuf>)> {
    let mut capture = Capture::new();
    let mut unit_files = Vec::new();
    let mut dropins = Vec::new();
    for root in &manager.paths {
        if let Some(parent) = capture.directory(root)? {
            let file = root.join(UNIT);
            if capture.regular(&parent, &file)? {
                unit_files.push(file)
            }
        }
        for kind in DROPINS {
            dropins.extend(capture.dropins(root, kind)?);
        }
    }
    if let Some(parent) = capture.directory(Path::new("/etc/default"))? {
        capture.regular(&parent, Path::new("/etc/default/aegis-client"))?;
    }
    Ok((capture, unit_files, dropins))
}
impl UnitNamespaceSnapshot {
    pub(crate) fn capture(lock: &InstallLock) -> Result<Self> {
        Self::capture_checked(|| lock.revalidate())
    }
    /// Observation for a child of the real installer shell. The inherited
    /// capability can only scan/revalidate; it cannot enter any publication,
    /// restoration or unit mutation method taking InstallLock.
    pub(crate) fn capture_inherited_read_only(lock: &InheritedInstallReadLock) -> Result<Self> {
        Self::capture_checked(|| lock.revalidate())
    }
    fn capture_checked(check: impl Fn() -> Result<()>) -> Result<Self> {
        check()?;
        let manager = observe_manager()?;
        let (capture, unit_files, dropins) = scan(&manager)?;
        validate_effective(&manager, &unit_files, &dropins)?;
        need(observe_manager()? == manager)?;
        check()?;
        let record = NamespaceRecord::seal(manager, capture.nodes.into_values().collect())?;
        let result = Self {
            record,
            held: capture.held,
        };
        result.revalidate_held()?;
        Ok(result)
    }
    pub(crate) fn record(&self) -> &NamespaceRecord {
        &self.record
    }
    /// Source-backed exact closed-role parent selection. The returned duplicate
    /// pins the verified parent inode; later mutation still requires actual
    /// protected generation reopen and stopped admission under the worker lock.
    pub(crate) fn open_original_role_parent(
        &self,
        role: ManagedRole,
        lock: &InstallLock,
    ) -> Result<OwnedFd> {
        self.revalidate(lock)?;
        let parent = role.fixed_path().parent().ok_or(REFUSED)?;
        let expected = self
            .record
            .nodes
            .iter()
            .find(|n| n.path == parent && n.kind == "directory")
            .and_then(|n| n.metadata.as_ref())
            .ok_or(REFUSED)?;
        let held = self.held.iter().find(|h| h.path == parent).ok_or(REFUSED)?;
        need(held.metadata == *expected && metadata(&stat(&held.file)?, false) == *expected)?;
        let result = held.file.try_clone().map_err(err)?;
        need(metadata(&stat(&result)?, false) == *expected)?;
        self.revalidate(lock)?;
        Ok(result)
    }
    fn revalidate_held(&self) -> Result<()> {
        for held in &self.held {
            let m = stat(&held.file)?;
            let regular = held.metadata.mode & libc::S_IFMT == libc::S_IFREG;
            need(metadata(&m, regular) == held.metadata)?;
            // Exact pathname/negative-witness reconstruction is supplied by
            // recapture in revalidate, never by this held-FD check alone.
            need(held.path.is_absolute())?;
        }
        Ok(())
    }
    pub(crate) fn reopen(record: &NamespaceRecord, lock: &InstallLock) -> Result<Self> {
        record.validate()?;
        let value = Self::capture(lock)?;
        value.record.matches_namespace_contents(record)?;
        // Preserve the sealed transaction identity. Fresh held descriptors pin
        // the current directory instances; their inode numbers are not new
        // authority and must not rewrite the protected original record.
        Ok(Self {
            record: record.clone(),
            held: value.held,
        })
    }
    pub(crate) fn revalidate(&self, lock: &InstallLock) -> Result<()> {
        self.revalidate_held()?;
        let current = Self::capture(lock)?;
        current.record.matches_namespace_contents(&self.record)
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum ManagedRole {
    BaseUnit,
    Environment,
    Dropins,
}
impl ManagedRole {
    pub(crate) fn fixed_path(self) -> &'static Path {
        Path::new(match self {
            Self::BaseUnit => "/etc/systemd/system/aegis-client.service",
            Self::Environment => "/etc/default/aegis-client",
            Self::Dropins => "/etc/systemd/system/aegis-client.service.d",
        })
    }
    fn contains(self, path: &Path) -> bool {
        if self == Self::Dropins {
            path.starts_with(self.fixed_path())
        } else {
            path == self.fixed_path()
        }
    }
}
/// Opaque record minted from actual authenticated publication receipt + observed
/// role nodes. Deserialize alone cannot authorize it: protected receipt/intent
/// and the exact worker epoch are authenticated on every use by RootContext.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedTransition {
    schema: u32,
    role: ManagedRole,
    original_namespace: String,
    epoch: [u8; 32],
    receipt_semantics_sha256: String,
    original_role_sha256: String,
    nodes: Vec<Node>,
    generation: String,
}
impl OwnedTransition {
    pub(crate) fn role(&self) -> ManagedRole {
        self.role
    }
    pub(crate) fn epoch(&self) -> &[u8; 32] {
        &self.epoch
    }
    pub(crate) fn receipt_semantics_sha256(&self) -> &str {
        &self.receipt_semantics_sha256
    }
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }
    fn compute(&self) -> Result<String> {
        Ok(digest(
            &serde_json::to_vec(&(
                self.schema,
                self.role,
                &self.original_namespace,
                self.epoch,
                &self.receipt_semantics_sha256,
                &self.original_role_sha256,
                &self.nodes,
            ))
            .map_err(err)?,
        ))
    }
    fn validate(&self, original: &NamespaceRecord, epoch: [u8; 32]) -> Result<()> {
        need(
            self.schema == 1
                && self.epoch == epoch
                && self.original_namespace == original.generation
                && self.compute()? == self.generation,
        )?;
        need(
            self.nodes.len() <= RECORD_LIMIT
                && self.nodes.windows(2).all(|w| w[0].path < w[1].path)
                && self.nodes.iter().all(|n| {
                    normal(&n.path)
                        && self.role.contains(&n.path)
                        && n.parent == n.path.parent().unwrap_or(Path::new("/"))
                        && n.name == n.path.file_name().unwrap_or_default().to_string_lossy()
                        && matches!(n.kind.as_str(), "regular" | "directory")
                }),
        )?;
        need(self.original_role_sha256 == role_digest(original, self.role)?)?;
        for node in &self.nodes {
            let metadata = node.metadata.as_ref().ok_or(REFUSED)?;
            need(metadata.uid == 0 && metadata.gid == 0 && metadata.mode & 0o022 == 0)?;
            if node.kind == "regular" {
                need(
                    metadata.mode & libc::S_IFMT == libc::S_IFREG
                        && metadata.links == 1
                        && metadata.size >= 0
                        && metadata.size <= FILE_LIMIT as i64
                        && node.sha256.as_ref().is_some_and(|h| {
                            h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())
                        }),
                )?;
            } else {
                need(metadata.mode & libc::S_IFMT == libc::S_IFDIR && node.sha256.is_none())?;
            }
        }
        if self.role == ManagedRole::Dropins {
            need(
                self.nodes
                    .iter()
                    .any(|n| n.path == self.role.fixed_path() && n.kind == "directory"),
            )?;
        } else {
            need(
                self.nodes.len() == 1
                    && self.nodes[0].path == self.role.fixed_path()
                    && self.nodes[0].kind == "regular",
            )?;
        }
        need(
            self.receipt_semantics_sha256.len() == 64
                && self
                    .receipt_semantics_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
        )
    }
}
pub(crate) trait TransitionAuthority {
    fn transaction_epoch(&self) -> Result<[u8; 32]>;
    /// Actual protected intent/receipt SHA, role and epoch checks; no default.
    fn authenticate_owned_transition(&self, transition: &OwnedTransition) -> Result<()>;
    fn sealed_daemon_reload_receipt(
        &self,
    ) -> Result<Option<crate::profile_auto_stopped_service::DaemonReloadReceipt>>;
    fn authenticate_daemon_reload_receipt(
        &self,
        receipt: &crate::profile_auto_stopped_service::DaemonReloadReceipt,
    ) -> Result<()>;
}
fn current_manager_epoch<A: TransitionAuthority>(
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
    authority: &A,
) -> Result<Manager> {
    let epoch = authority.transaction_epoch()?;
    let manager = match authority.sealed_daemon_reload_receipt()? {
        None => original.manager.clone(),
        Some(receipt) => {
            authority.authenticate_daemon_reload_receipt(&receipt)?;
            receipt.validate_namespace_binding(original, forward, epoch)?;
            receipt.accepted_namespace().manager.clone()
        }
    };
    need(authority.transaction_epoch()? == epoch)?;
    Ok(manager)
}

fn role_digest(record: &NamespaceRecord, role: ManagedRole) -> Result<String> {
    let nodes: Vec<_> = record
        .nodes
        .iter()
        .filter(|n| role.contains(&n.path))
        .collect();
    need(!nodes.is_empty())?;
    Ok(digest(&serde_json::to_vec(&nodes).map_err(err)?))
}
fn scoped_nodes(
    original: &NamespaceRecord,
    records: &[OwnedTransition],
    epoch: [u8; 32],
) -> Result<BTreeMap<PathBuf, Node>> {
    original.validate()?;
    need(records.len() <= 3)?;
    let mut roles = BTreeSet::new();
    let mut expected: BTreeMap<_, _> = original
        .nodes
        .iter()
        .cloned()
        .map(|n| (n.path.clone(), n))
        .collect();
    for transition in records {
        transition.validate(original, epoch)?;
        need(roles.insert(transition.role))?;
        expected.retain(|path, _| !transition.role.contains(path));
        for node in &transition.nodes {
            need(expected.insert(node.path.clone(), node.clone()).is_none())?;
        }
    }
    Ok(expected)
}
fn expected_nodes<A: TransitionAuthority>(
    original: &NamespaceRecord,
    records: &[OwnedTransition],
    authority: &A,
) -> Result<BTreeMap<PathBuf, Node>> {
    let epoch = authority.transaction_epoch()?;
    let expected = scoped_nodes(original, records, epoch)?;
    for transition in records {
        authority.authenticate_owned_transition(transition)?;
    }
    need(authority.transaction_epoch()? == epoch)?;
    Ok(expected)
}
// PID 1 owns these runtime lookup roots. It may recreate one during an
// ordinary daemon-reload (new inode) and trims empty generator roots after a
// reload. Every boot starts with none of /run's transient state: systemd
// creates /run/systemd/transient lazily for the boot's first transient unit,
// for example the scope of the first login session, and generator.early/.late
// only when a generator writes there. Neither the inode nor the presence of
// such a root is configuration identity while it holds nothing for the fixed
// unit: an existing root whose only recorded descendants are this unit's
// exact negative witnesses is the same namespace as an absent root. Device,
// ownership, permissions, the complete node roster, every unit-file and
// drop-in fact and manager observations remain authenticated. Held
// descriptors still pin each individual scan against concurrent changes.
const RUNTIME_LOOKUP_ROOTS: [&str; 4] = [
    "/run/systemd/generator",
    "/run/systemd/generator.early",
    "/run/systemd/generator.late",
    "/run/systemd/transient",
];
fn runtime_root_descendants<'a>(
    nodes: &'a BTreeMap<PathBuf, Node>,
    root: &'a Path,
) -> impl Iterator<Item = &'a Node> + 'a {
    nodes
        .iter()
        .filter(move |(path, _)| path.as_path() != root && path.starts_with(root))
        .map(|(_, node)| node)
}
fn runtime_root_node<'a>(nodes: &'a BTreeMap<PathBuf, Node>, root: &Path) -> Result<&'a Node> {
    let node = nodes.get(root).ok_or(REFUSED)?;
    let parent = nodes.get(root.parent().ok_or(REFUSED)?).ok_or(REFUSED)?;
    need(
        node.path == root
            && Some(node.parent.as_path()) == root.parent()
            && root.file_name().and_then(|name| name.to_str()) == Some(node.name.as_str())
            && node.sha256.is_none()
            && parent.kind == "directory"
            && parent.sha256.is_none()
            && parent.metadata.is_some(),
    )?;
    Ok(node)
}
/// A root exactly as PID1 creates it: root-owned 0755 on its parent's
/// filesystem, recording only the fixed unit's negative witnesses.
fn empty_runtime_root(nodes: &BTreeMap<PathBuf, Node>, root: &Path) -> Result<()> {
    let node = runtime_root_node(nodes, root)?;
    let parent = nodes
        .get(root.parent().ok_or(REFUSED)?)
        .and_then(|parent| parent.metadata.as_ref())
        .ok_or(REFUSED)?;
    let meta = node.metadata.as_ref().ok_or(REFUSED)?;
    need(
        node.kind == "directory"
            && *meta
                == (Metadata {
                    device: parent.device,
                    inode: meta.inode,
                    uid: 0,
                    gid: 0,
                    mode: libc::S_IFDIR | 0o755,
                    links: 0,
                    size: 0,
                    mtime_sec: 0,
                    mtime_nsec: 0,
                    ctime_sec: 0,
                    ctime_nsec: 0,
                }),
    )?;
    let mut witnesses = BTreeMap::new();
    witnesses.insert(root.join(UNIT), "missing-file");
    for kind in DROPINS {
        witnesses.insert(root.join(kind), "missing-directory");
    }
    let mut seen = 0;
    for child in runtime_root_descendants(nodes, root) {
        need(
            witnesses.get(&child.path) == Some(&child.kind.as_str())
                && child.parent == root
                && child.metadata.is_none()
                && child.sha256.is_none(),
        )?;
        seen += 1;
    }
    need(seen == witnesses.len())
}
/// The single negative witness `scan` records for a root PID1 has not created.
fn absent_runtime_root(nodes: &BTreeMap<PathBuf, Node>, root: &Path) -> Result<()> {
    let node = runtime_root_node(nodes, root)?;
    need(
        node.kind == "missing-directory"
            && node.metadata.is_none()
            && runtime_root_descendants(nodes, root).next().is_none(),
    )
}
fn rebind_runtime_directory_inodes(
    expected: &BTreeMap<PathBuf, Node>,
    actual: &BTreeMap<PathBuf, Node>,
) -> Result<BTreeMap<PathBuf, Node>> {
    let mut rebound = expected.clone();
    for path in RUNTIME_LOOKUP_ROOTS {
        let path = Path::new(path);
        let (Some(before), Some(after)) = (rebound.get(path).cloned(), actual.get(path)) else {
            continue;
        };
        if before == *after {
            continue;
        }
        if before.kind == "directory" && after.kind == "directory" {
            need(
                before.path == after.path
                    && before.parent == after.parent
                    && before.name == after.name
                    && before.sha256.is_none()
                    && after.sha256.is_none(),
            )?;
            let mut old = before.metadata.clone().ok_or(REFUSED)?;
            let new = after.metadata.as_ref().ok_or(REFUSED)?;
            need(old.device == new.device && old.uid == 0 && new.uid == 0)?;
            old.inode = new.inode;
            need(old == *new)?;
            rebound.insert(path.to_path_buf(), after.clone());
            continue;
        }
        // Presence changed: only an exact absent <-> empty pair is equivalent.
        if before.kind == "directory" {
            empty_runtime_root(&rebound, path)?;
            absent_runtime_root(actual, path)?;
        } else {
            absent_runtime_root(&rebound, path)?;
            empty_runtime_root(actual, path)?;
        }
        rebound.retain(|node, _| !node.starts_with(path));
        for (node_path, node) in actual.iter().filter(|(p, _)| p.starts_with(path)) {
            rebound.insert(node_path.clone(), node.clone());
        }
    }
    need(&rebound == actual)?;
    Ok(rebound)
}
fn runtime_nodes_match(
    expected: &BTreeMap<PathBuf, Node>,
    actual: &BTreeMap<PathBuf, Node>,
) -> bool {
    rebind_runtime_directory_inodes(expected, actual).is_ok()
}
impl NamespaceRecord {
    fn matches_namespace_contents(&self, original: &Self) -> Result<()> {
        self.validate()?;
        original.validate()?;
        need(self.manager == original.manager)?;
        let nodes = |record: &Self| {
            record
                .nodes
                .iter()
                .cloned()
                .map(|node| (node.path.clone(), node))
                .collect::<BTreeMap<_, _>>()
        };
        // Duplicate paths cannot disappear when constructing the comparison.
        let expected = nodes(original);
        let actual = nodes(self);
        need(expected.len() == original.nodes.len() && actual.len() == self.nodes.len())?;
        rebind_runtime_directory_inodes(&expected, &actual).map(|_| ())
    }
}
fn minted_transition<A: TransitionAuthority>(
    authority: &A,
    original: &NamespaceRecord,
    previous: &[OwnedTransition],
    role: ManagedRole,
    receipt_semantics_sha256: String,
    lock: &InstallLock,
) -> Result<OwnedTransition> {
    lock.revalidate()?;
    let epoch = authority.transaction_epoch()?;
    let mut expected = expected_nodes(original, previous, authority)?;
    let manager = current_manager_epoch(original, previous, authority)?;
    need(!previous.iter().any(|r| r.role == role) && observe_manager()? == manager)?;
    let (capture, _, _) = scan(&manager)?;
    let nodes: Vec<_> = capture
        .nodes
        .values()
        .filter(|n| role.contains(&n.path))
        .cloned()
        .collect();
    expected.retain(|p, _| !role.contains(p));
    for node in &nodes {
        need(expected.insert(node.path.clone(), node.clone()).is_none())?;
    }
    need(runtime_nodes_match(&expected, &capture.nodes) && observe_manager()? == manager)?;
    lock.revalidate()?;
    need(authority.transaction_epoch()? == epoch)?;
    let mut record = OwnedTransition {
        schema: 1,
        role,
        original_namespace: original.generation.clone(),
        epoch,
        receipt_semantics_sha256,
        original_role_sha256: role_digest(original, role)?,
        nodes,
        generation: String::new(),
    };
    record.generation = record.compute()?;
    record.validate(original, record.epoch)?;
    Ok(record)
}
fn witness_metadata(
    m: &crate::profile_auto_unit_policy::linux::OriginalNamespaceMetadata,
) -> Metadata {
    Metadata {
        device: m.device,
        inode: m.inode,
        uid: m.uid,
        gid: m.gid,
        mode: m.mode,
        links: m.links,
        size: m.size,
        mtime_sec: m.mtime_sec,
        mtime_nsec: m.mtime_nsec,
        ctime_sec: m.ctime_sec,
        ctime_nsec: m.ctime_nsec,
    }
}
pub(crate) fn singleton_receipt_digest(
    receipt: &crate::profile_auto_unit_policy::linux::Receipt,
) -> Result<String> {
    let mut bytes = b"aegis-owned-unit-singleton-receipt-v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(receipt).map_err(err)?);
    Ok(digest(&bytes))
}
pub(crate) fn dropin_receipt_digest(
    receipt: &crate::profile_auto_publication::linux::PublicationReceipt,
) -> Result<String> {
    let mut bytes = b"aegis-owned-unit-dropin-receipt-v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(receipt.intent()).map_err(err)?);
    bytes.extend_from_slice(&receipt.generation().witness()?);
    Ok(digest(&bytes))
}
pub(crate) fn mint_singleton<
    A: TransitionAuthority,
    C: crate::profile_auto_unit_policy::linux::Context,
>(
    authority: &A,
    context: &C,
    original: &NamespaceRecord,
    previous: &[OwnedTransition],
    receipt: &crate::profile_auto_unit_policy::linux::Receipt,
    lock: &InstallLock,
) -> Result<OwnedTransition> {
    use crate::profile_auto_unit_policy::linux as policy;
    policy::verify(context, receipt)?;
    need(
        context.epoch()? == authority.transaction_epoch()?
            && receipt.publication_epoch() == authority.transaction_epoch()?,
    )?;
    let witness = receipt.original_namespace_witness();
    let role = match witness.role {
        policy::LeafRole::BaseUnit => ManagedRole::BaseUnit,
        policy::LeafRole::Environment => ManagedRole::Environment,
    };
    let node = original
        .nodes
        .iter()
        .find(|n| n.path == role.fixed_path())
        .ok_or(REFUSED)?;
    match (&witness.metadata, witness.sha256) {
        (None, None) => {
            need(node.kind == "missing-file" && node.metadata.is_none() && node.sha256.is_none())?
        }
        (Some(m), Some(hash)) => need(
            node.kind == "regular"
                && node.metadata.as_ref() == Some(&witness_metadata(m))
                && node.sha256.as_deref() == Some(hex::encode(hash).as_str()),
        )?,
        _ => return Err(REFUSED),
    }
    minted_transition(
        authority,
        original,
        previous,
        role,
        singleton_receipt_digest(receipt)?,
        lock,
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FsId {
    dev: u64,
    ino: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FsMetadata {
    id: FsId,
    mode: u32,
    uid: u32,
    gid: u32,
    links: u64,
    size: i64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
fn validate_dropin_original<C: crate::profile_auto_unit_policy::linux::DropinContext>(
    context: &C,
    original: &NamespaceRecord,
    original_files: &BTreeMap<PathBuf, Vec<u8>>,
    directories: &BTreeSet<PathBuf>,
) -> Result<()> {
    let role = ManagedRole::Dropins;
    let nodes: Vec<_> = original
        .nodes
        .iter()
        .filter(|n| role.contains(&n.path))
        .collect();
    need(!nodes.is_empty())?;
    let generation = context.original_generation()?;
    match generation {
        None => need(
            nodes.len() == 1
                && nodes[0].path == role.fixed_path()
                && nodes[0].kind == "missing-directory"
                && original_files.is_empty()
                && directories.is_empty(),
        )?,
        Some(generation) => {
            let witness = generation.witness()?;
            need(witness.len() <= TOTAL_LIMIT)?;
            let wire: BTreeMap<PathBuf, FsMetadata> =
                serde_json::from_slice(&witness).map_err(err)?;
            need(wire.len() == nodes.len())?;
            let mut expected_files: BTreeMap<PathBuf, String> = BTreeMap::new();
            let mut expected_dirs = BTreeSet::new();
            for node in nodes {
                let relative = node.path.strip_prefix(role.fixed_path()).map_err(err)?;
                let w = wire.get(relative).ok_or(REFUSED)?;
                let m = node.metadata.as_ref().ok_or(REFUSED)?;
                need(
                    w.id.dev == m.device
                        && w.id.ino == m.inode
                        && w.mode == m.mode
                        && w.uid == m.uid
                        && w.gid == m.gid,
                )?;
                if node.kind == "regular" {
                    need(
                        w.links == m.links
                            && w.size == m.size
                            && w.mtime == m.mtime_sec
                            && w.mtime_ns == m.mtime_nsec
                            && w.ctime == m.ctime_sec
                            && w.ctime_ns == m.ctime_nsec,
                    )?;
                    expected_files.insert(relative.into(), node.sha256.clone().ok_or(REFUSED)?);
                } else {
                    need(node.kind == "directory")?;
                    if !relative.as_os_str().is_empty() {
                        expected_dirs.insert(relative.into());
                    }
                }
            }
            need(expected_dirs == *directories && expected_files.len() == original_files.len())?;
            for (path, hash) in expected_files {
                need(original_files.get(&path).is_some_and(|b| digest(b) == hash))?;
            }
        }
    }
    Ok(())
}
pub(crate) struct DropinTransitionInputs<'a> {
    pub original: &'a NamespaceRecord,
    pub previous: &'a [OwnedTransition],
    pub compiled: &'a crate::profile_auto_unit_policy::linux::CompiledPolicy,
    pub directories: &'a BTreeSet<PathBuf>,
    pub original_files: &'a BTreeMap<PathBuf, Vec<u8>>,
    pub receipt: &'a crate::profile_auto_publication::linux::PublicationReceipt,
}
pub(crate) fn mint_dropins<
    A: TransitionAuthority,
    C: crate::profile_auto_unit_policy::linux::DropinContext,
>(
    authority: &A,
    context: &C,
    inputs: DropinTransitionInputs<'_>,
    lock: &InstallLock,
) -> Result<OwnedTransition> {
    let DropinTransitionInputs {
        original,
        previous,
        compiled,
        directories,
        original_files,
        receipt,
    } = inputs;
    crate::profile_auto_unit_policy::linux::verify_dropins(
        context,
        compiled,
        directories,
        receipt,
    )?;
    need(context.epoch()? == authority.transaction_epoch()?)?;
    validate_dropin_original(context, original, original_files, directories)?;
    // Unknown original file bytes cannot be changed merely because their tree
    // belongs to our publisher. The device guard exception below requires the
    // compiler's exact old/owned hook bytes for this binary and timeout.
    for (path, bytes) in original_files {
        if path == Path::new("30-device-egress-guard.conf")
            && compiled.dropins.get(path) != Some(bytes)
        {
            crate::profile_auto_unit_policy::linux::verify_owned_guard_transition(compiled, bytes)?;
        } else if path != Path::new("10-dedicated-uid.conf")
            && path != Path::new("20-ipv6-tun.conf")
        {
            need(compiled.dropins.get(path) == Some(bytes))?;
        }
    }
    minted_transition(
        authority,
        original,
        previous,
        ManagedRole::Dropins,
        dropin_receipt_digest(receipt)?,
        lock,
    )
}

/// A restoration is never a forward publication. Its protected receipt must
/// authenticate the actual rollback readback and the exact forward predecessor.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedRestoration {
    schema: u32,
    role: ManagedRole,
    original_namespace: String,
    epoch: [u8; 32],
    forward_generation: String,
    restoration_receipt_sha256: String,
    nodes: Vec<Node>,
    generation: String,
}
impl OwnedRestoration {
    pub(crate) fn role(&self) -> ManagedRole {
        self.role
    }
    pub(crate) fn epoch(&self) -> &[u8; 32] {
        &self.epoch
    }
    pub(crate) fn forward_generation(&self) -> &str {
        &self.forward_generation
    }
    pub(crate) fn restoration_receipt_sha256(&self) -> &str {
        &self.restoration_receipt_sha256
    }
    pub(crate) fn generation(&self) -> &str {
        &self.generation
    }
    fn compute(&self) -> Result<String> {
        Ok(digest(
            &serde_json::to_vec(&(
                self.schema,
                self.role,
                &self.original_namespace,
                self.epoch,
                &self.forward_generation,
                &self.restoration_receipt_sha256,
                &self.nodes,
            ))
            .map_err(err)?,
        ))
    }
    fn validate(
        &self,
        original: &NamespaceRecord,
        forward: &OwnedTransition,
        epoch: [u8; 32],
    ) -> Result<()> {
        forward.validate(original, epoch)?;
        need(
            self.schema == 1
                && self.role == forward.role
                && self.epoch == epoch
                && self.original_namespace == original.generation
                && self.forward_generation == forward.generation
                && self.compute()? == self.generation,
        )?;
        need(
            self.restoration_receipt_sha256.len() == 64
                && self
                    .restoration_receipt_sha256
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit()),
        )?;
        // Rename/exchange changes ctime of the retained original inode. Only
        // ctime is read back anew under actual restoration-receipt authority;
        // no original identity, attribute, byte or absence witness is relaxed.
        restored_role_matches(original, self.role, &self.nodes)
    }
}
fn restored_role_matches(
    original: &NamespaceRecord,
    role: ManagedRole,
    nodes: &[Node],
) -> Result<()> {
    let old: Vec<_> = original
        .nodes
        .iter()
        .filter(|n| role.contains(&n.path))
        .collect();
    need(
        !old.is_empty()
            && old.len() == nodes.len()
            && nodes.len() <= RECORD_LIMIT
            && nodes.windows(2).all(|w| w[0].path < w[1].path),
    )?;
    for (before, after) in old.into_iter().zip(nodes) {
        need(
            before.path == after.path
                && before.parent == after.parent
                && before.name == after.name
                && before.kind == after.kind
                && before.sha256 == after.sha256,
        )?;
        match (&before.metadata, &after.metadata) {
            (None, None) => need(matches!(
                before.kind.as_str(),
                "missing-file" | "missing-directory"
            ))?,
            (Some(old), Some(now)) => {
                let mut expected = old.clone();
                if before.kind == "regular" {
                    expected.ctime_sec = now.ctime_sec;
                    expected.ctime_nsec = now.ctime_nsec;
                }
                need(expected == *now)?;
            }
            _ => return Err(REFUSED),
        }
    }
    Ok(())
}
pub(crate) trait RestorationAuthority: TransitionAuthority {
    /// Reopen the sealed actual restoration intent/receipt, verify its role,
    /// epoch and predecessor, then compute the semantic digest. No default.
    fn authenticate_owned_restoration(&self, restoration: &OwnedRestoration) -> Result<()>;
}
fn restored_scoped_nodes(
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
    restored: &[OwnedRestoration],
    epoch: [u8; 32],
) -> Result<BTreeMap<PathBuf, Node>> {
    let mut expected = scoped_nodes(original, forward, epoch)?;
    need(restored.len() <= 3)?;
    let mut roles = BTreeSet::new();
    for restoration in restored {
        need(roles.insert(restoration.role))?;
        let predecessor = forward
            .iter()
            .find(|r| r.role == restoration.role)
            .ok_or(REFUSED)?;
        restoration.validate(original, predecessor, epoch)?;
        expected.retain(|path, _| !restoration.role.contains(path));
        for node in &restoration.nodes {
            need(expected.insert(node.path.clone(), node.clone()).is_none())?;
        }
    }
    Ok(expected)
}

/// Read-only body projection for comparing separately authenticated stages.
/// Receipt generations include a stage epoch and cannot be compared across
/// stage roots; these fixed-role nodes can.
#[derive(Serialize)]
pub(crate) struct InspectedRoleNode {
    role: &'static str,
    path: PathBuf,
    kind: String,
    sha256: Option<String>,
    uid: Option<u32>,
    gid: Option<u32>,
    mode: Option<u32>,
    size: Option<i64>,
    device: Option<u64>,
    inode: Option<u64>,
}

#[cfg(test)]
pub(crate) fn test_inspected_role_nodes() -> Vec<InspectedRoleNode> {
    inspected_role_nodes(
        [
            "/etc/systemd/system/aegis-client.service",
            "/etc/default/aegis-client",
        ]
        .into_iter()
        .map(|value| {
            let path = PathBuf::from(value);
            Node {
                parent: path.parent().unwrap().into(),
                name: path.file_name().unwrap().to_str().unwrap().into(),
                path,
                kind: "missing-file".into(),
                metadata: None,
                sha256: None,
            }
        }),
    )
}

fn inspected_role_nodes(nodes: impl IntoIterator<Item = Node>) -> Vec<InspectedRoleNode> {
    let mut result: Vec<_> = nodes
        .into_iter()
        .filter_map(|node| {
            let role = [
                ManagedRole::BaseUnit,
                ManagedRole::Environment,
                ManagedRole::Dropins,
            ]
            .into_iter()
            .find(|role| role.contains(&node.path))?;
            let metadata = node.metadata.as_ref();
            Some(InspectedRoleNode {
                role: match role {
                    ManagedRole::BaseUnit => "base-unit",
                    ManagedRole::Environment => "environment",
                    ManagedRole::Dropins => "dropins",
                },
                path: node.path,
                kind: node.kind,
                sha256: node.sha256,
                uid: metadata.map(|m| m.uid),
                gid: metadata.map(|m| m.gid),
                mode: metadata.map(|m| m.mode),
                size: metadata.map(|m| m.size),
                device: metadata.map(|m| m.device),
                inode: metadata.map(|m| m.inode),
            })
        })
        .collect();
    result.sort_by(|a, b| a.path.cmp(&b.path));
    result
}

pub(crate) fn inspect_record_roles(record: &NamespaceRecord) -> Result<Vec<InspectedRoleNode>> {
    record.check_generation()?;
    let nodes = inspected_role_nodes(record.nodes.clone());
    need(nodes.windows(2).all(|pair| pair[0].path != pair[1].path))?;
    Ok(nodes)
}

pub(crate) fn same_role_contents(a: &[InspectedRoleNode], b: &[InspectedRoleNode]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(a, b)| {
            a.role == b.role
                && a.path == b.path
                && a.kind == b.kind
                && a.sha256 == b.sha256
                && a.uid == b.uid
                && a.gid == b.gid
                && a.mode == b.mode
                && a.size == b.size
                && a.device == b.device
                && a.inode == b.inode
        })
}

pub(crate) fn inspect_role_chain(
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
    restored: &[OwnedRestoration],
    epoch: [u8; 32],
) -> Result<(Vec<InspectedRoleNode>, Vec<InspectedRoleNode>)> {
    original.check_generation()?;
    need(forward.len() == 3)?;
    let forward_roles: BTreeSet<_> = forward.iter().map(OwnedTransition::role).collect();
    need(
        forward_roles
            == BTreeSet::from([
                ManagedRole::BaseUnit,
                ManagedRole::Environment,
                ManagedRole::Dropins,
            ]),
    )?;
    let final_nodes = restored_scoped_nodes(original, forward, restored, epoch)?;
    let original_nodes = inspected_role_nodes(original.nodes.clone());
    let final_nodes = inspected_role_nodes(final_nodes.into_values());
    need(
        original_nodes
            .windows(2)
            .all(|pair| pair[0].path != pair[1].path),
    )?;
    need(
        final_nodes
            .windows(2)
            .all(|pair| pair[0].path != pair[1].path),
    )?;
    Ok((original_nodes, final_nodes))
}
fn authenticated_restored_nodes<A: RestorationAuthority>(
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
    restored: &[OwnedRestoration],
    authority: &A,
) -> Result<BTreeMap<PathBuf, Node>> {
    let epoch = authority.transaction_epoch()?;
    let mut expected = restored_scoped_nodes(original, forward, restored, epoch)?;
    for record in forward {
        authority.authenticate_owned_transition(record)?;
    }
    for record in restored {
        authority.authenticate_owned_restoration(record)?;
    }
    if let Some(receipt) = authority.sealed_daemon_reload_receipt()? {
        authority.authenticate_daemon_reload_receipt(&receipt)?;
        receipt.validate_namespace_binding(original, forward, epoch)?;
        let accepted = receipt.accepted_namespace();
        let forward_expected = scoped_nodes(original, forward, epoch)?;
        let accepted_nodes: BTreeMap<_, _> = accepted
            .nodes
            .iter()
            .cloned()
            .map(|node| (node.path.clone(), node))
            .collect();
        let rebound = rebind_runtime_directory_inodes(&forward_expected, &accepted_nodes)?;
        carry_accepted_runtime_roots(&mut expected, &forward_expected, &rebound)?;
    }
    need(authority.transaction_epoch()? == epoch)?;
    Ok(expected)
}
/// Carry the reload-accepted view of PID1's runtime lookup roots into the
/// restoration chain; every other node stays the authenticated chain's own.
/// `rebound` was proved equivalent to the forward chain by
/// rebind_runtime_directory_inodes (a new inode or an absent <-> empty root),
/// so each root's whole subtree is replaced, never only its root node. The
/// chain's own subtree must still be exactly the forward view it came from.
fn carry_accepted_runtime_roots(
    expected: &mut BTreeMap<PathBuf, Node>,
    forward_expected: &BTreeMap<PathBuf, Node>,
    rebound: &BTreeMap<PathBuf, Node>,
) -> Result<()> {
    for path in RUNTIME_LOOKUP_ROOTS {
        let root = Path::new(path);
        if !rebound.contains_key(root) {
            continue;
        }
        let subtree = |nodes: &BTreeMap<PathBuf, Node>| -> BTreeMap<PathBuf, Node> {
            nodes
                .iter()
                .filter(|(node, _)| node.starts_with(root))
                .map(|(node, value)| (node.clone(), value.clone()))
                .collect()
        };
        need(expected.contains_key(root) && subtree(expected) == subtree(forward_expected))?;
        expected.retain(|node, _| !node.starts_with(root));
        expected.extend(subtree(rebound));
    }
    Ok(())
}
/// Pre-reload rollback view. A changed manager generation is refused, rather
/// than rebasing the original namespace onto an unproved manager observation.
pub(crate) struct RestoredNamespaceView {
    original: NamespaceRecord,
    forward: Vec<OwnedTransition>,
    restored: Vec<OwnedRestoration>,
    manager: Manager,
    held: Vec<Held>,
}
impl RestoredNamespaceView {
    pub(crate) fn current_actor_absent(&self) -> bool {
        self.manager.unit["LoadState"] == "not-found"
    }
    pub(crate) fn reopen<A: RestorationAuthority>(
        original: &NamespaceRecord,
        forward: &[OwnedTransition],
        restored: &[OwnedRestoration],
        authority: &A,
        lock: &InstallLock,
    ) -> Result<Self> {
        lock.revalidate()?;
        let expected = authenticated_restored_nodes(original, forward, restored, authority)?;
        let manager = current_manager_epoch(original, forward, authority)?;
        need(observe_manager()? == manager)?;
        let (capture, _, _) = scan(&manager)?;
        need(runtime_nodes_match(&expected, &capture.nodes) && observe_manager()? == manager)?;
        lock.revalidate()?;
        Ok(Self {
            original: original.clone(),
            forward: forward.to_vec(),
            restored: restored.to_vec(),
            manager,
            held: capture.held,
        })
    }
    pub(crate) fn revalidate<A: RestorationAuthority>(
        &self,
        authority: &A,
        lock: &InstallLock,
    ) -> Result<()> {
        for h in &self.held {
            let regular = h.metadata.mode & libc::S_IFMT == libc::S_IFREG;
            need(metadata(&stat(&h.file)?, regular) == h.metadata)?;
        }
        Self::reopen(
            &self.original,
            &self.forward,
            &self.restored,
            authority,
            lock,
        )
        .map(|_| ())
    }
}

/// Pre-reload pending singleton topology. Only a genuine policy-held
/// readback may replace one role; every other protected witness is retained.
pub(crate) struct PendingSingletonNamespaceView {
    original: NamespaceRecord,
    forward: Vec<OwnedTransition>,
    restored: Vec<OwnedRestoration>,
    proof: crate::profile_auto_unit_policy::linux::PendingSingletonReadback,
    manager: Manager,
    held: Vec<Held>,
}
impl PendingSingletonNamespaceView {
    pub(crate) fn current_actor_absent(&self) -> bool {
        self.manager.unit["LoadState"] == "not-found"
    }
    pub(crate) fn reopen<
        A: RestorationAuthority,
        C: crate::profile_auto_unit_policy::linux::Context,
    >(
        original: &NamespaceRecord,
        forward: &[OwnedTransition],
        restored: &[OwnedRestoration],
        authority: &A,
        proof: crate::profile_auto_unit_policy::linux::PendingSingletonReadback,
        context: &C,
        lock: &InstallLock,
    ) -> Result<Self> {
        lock.revalidate()?;
        proof.revalidate(context)?;
        let mut expected = authenticated_restored_nodes(original, forward, restored, authority)?;
        let manager = current_manager_epoch(original, forward, authority)?;
        need(observe_manager()? == manager)?;
        let (capture, _, _) = scan(&manager)?;
        let witness = proof.target_witness();
        let role = match witness.role {
            crate::profile_auto_unit_policy::linux::LeafRole::BaseUnit => ManagedRole::BaseUnit,
            crate::profile_auto_unit_policy::linux::LeafRole::Environment => {
                ManagedRole::Environment
            }
        };
        let nodes: Vec<_> = capture
            .nodes
            .values()
            .filter(|n| role.contains(&n.path))
            .cloned()
            .collect();
        need(nodes.len() == 1 && nodes[0].path == role.fixed_path())?;
        match (&witness.metadata, witness.sha256) {
            (None, None) => need(
                nodes[0].kind == "missing-file"
                    && nodes[0].metadata.is_none()
                    && nodes[0].sha256.is_none(),
            )?,
            (Some(m), Some(hash)) => need(
                nodes[0].kind == "regular"
                    && nodes[0].metadata.as_ref() == Some(&witness_metadata(m))
                    && nodes[0].sha256.as_deref() == Some(hex::encode(hash).as_str()),
            )?,
            _ => return Err(REFUSED),
        }
        expected.retain(|path, _| !role.contains(path));
        for node in nodes {
            need(expected.insert(node.path.clone(), node).is_none())?;
        }
        need(runtime_nodes_match(&expected, &capture.nodes) && observe_manager()? == manager)?;
        proof.revalidate(context)?;
        lock.revalidate()?;
        Ok(Self {
            original: original.clone(),
            forward: forward.to_vec(),
            restored: restored.to_vec(),
            proof,
            manager,
            held: capture.held,
        })
    }
    pub(crate) fn revalidate<
        A: RestorationAuthority,
        C: crate::profile_auto_unit_policy::linux::Context,
    >(
        &self,
        authority: &A,
        context: &C,
        lock: &InstallLock,
    ) -> Result<()> {
        lock.revalidate()?;
        self.proof.revalidate(context)?;
        need(
            current_manager_epoch(&self.original, &self.forward, authority)? == self.manager
                && observe_manager()? == self.manager,
        )?;
        let mut expected =
            authenticated_restored_nodes(&self.original, &self.forward, &self.restored, authority)?;
        let role = match self.proof.role() {
            crate::profile_auto_unit_policy::linux::LeafRole::BaseUnit => ManagedRole::BaseUnit,
            crate::profile_auto_unit_policy::linux::LeafRole::Environment => {
                ManagedRole::Environment
            }
        };
        let (capture, _, _) = scan(&self.manager)?;
        expected.retain(|p, _| !role.contains(p));
        for node in capture.nodes.values().filter(|n| role.contains(&n.path)) {
            need(expected.insert(node.path.clone(), node.clone()).is_none())?;
        }
        // The typed proof revalidates the exact target node/hash; scanning
        // all remaining roles forbids unrelated changes during recovery.
        need(runtime_nodes_match(&expected, &capture.nodes))?;
        for h in &self.held {
            let regular = h.metadata.mode & libc::S_IFMT == libc::S_IFREG;
            need(metadata(&stat(&h.file)?, regular) == h.metadata)?;
        }
        self.proof.revalidate(context)?;
        need(observe_manager()? == self.manager)?;
        lock.revalidate()
    }
}
/// Accepted manager/new-runtime custody remains valid while owned unit files
/// are restored. This opaque view preserves all original/forward/restored nodes.
pub(crate) struct RestorationManagerEpoch {
    accepted: crate::profile_auto_stopped_service::DaemonReloadReceipt,
    original: NamespaceRecord,
    forward: Vec<OwnedTransition>,
    view: RestoredNamespaceView,
}
impl RestorationManagerEpoch {
    pub(crate) fn runtime_identity(&self) -> (u32, u32) {
        self.accepted.runtime_identity()
    }
    pub(crate) fn accepted_receipt(
        &self,
    ) -> &crate::profile_auto_stopped_service::DaemonReloadReceipt {
        &self.accepted
    }
    pub(crate) fn reopen<A: RestorationAuthority>(
        original: &NamespaceRecord,
        forward: &[OwnedTransition],
        restored: &[OwnedRestoration],
        authority: &A,
        lock: &InstallLock,
    ) -> Result<Self> {
        lock.revalidate()?;
        let accepted = authority.sealed_daemon_reload_receipt()?.ok_or(REFUSED)?;
        authority.authenticate_daemon_reload_receipt(&accepted)?;
        accepted.validate_namespace_binding(original, forward, authority.transaction_epoch()?)?;
        let view = RestoredNamespaceView::reopen(original, forward, restored, authority, lock)?;
        let result = Self {
            accepted,
            original: original.clone(),
            forward: forward.to_vec(),
            view,
        };
        result.revalidate(authority, lock)?;
        Ok(result)
    }
    pub(crate) fn revalidate<A: RestorationAuthority>(
        &self,
        authority: &A,
        lock: &InstallLock,
    ) -> Result<()> {
        let actual = authority.sealed_daemon_reload_receipt()?.ok_or(REFUSED)?;
        authority.authenticate_daemon_reload_receipt(&actual)?;
        need(
            serde_json::to_vec(&actual).map_err(err)?
                == serde_json::to_vec(&self.accepted).map_err(err)?,
        )?;
        self.accepted.validate_namespace_binding(
            &self.original,
            &self.forward,
            authority.transaction_epoch()?,
        )?;
        self.view.revalidate(authority, lock)
    }
}
impl NamespaceRecord {
    pub(crate) fn matches_original_manager(&self, original: &NamespaceRecord) -> Result<()> {
        self.validate()?;
        original.validate()?;
        need(self.manager == original.manager)
    }
}
pub(crate) fn validate_restored_manager_namespace<A: RestorationAuthority>(
    actual: &NamespaceRecord,
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
    restored: &[OwnedRestoration],
    authority: &A,
) -> Result<()> {
    actual.matches_original_manager(original)?;
    need(restored.len() == 3 && forward.len() == 3)?;
    let expected = authenticated_restored_nodes(original, forward, restored, authority)?;
    let actual_nodes = actual
        .nodes
        .iter()
        .map(|n| (n.path.clone(), n.clone()))
        .collect::<BTreeMap<_, _>>();
    // Fresh capture requires RestoreReloadCompleted; later callers authenticate
    // the protected restored-manager receipt before this pure comparison. Only
    // runtime lookup-directory inodes, or the presence of such a root that
    // holds nothing for this unit, may also change during unrelated PID 1
    // activity; all unit-file facts remain equal to the sealed restoration chain.
    rebind_runtime_directory_inodes(&expected, &actual_nodes).map(|_| ())
}
pub(crate) fn capture_restored_manager_namespace<
    A: crate::profile_auto_stopped_service::ManagerRestorationAuthority,
>(
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
    restored: &[OwnedRestoration],
    authority: &A,
    completed: &crate::profile_auto_stopped_service::RestoreReloadCompleted,
    lock: &InstallLock,
) -> Result<NamespaceRecord> {
    completed.validate(authority, original, forward, restored)?;
    let actual = UnitNamespaceSnapshot::capture(lock)?;
    validate_restored_manager_namespace(actual.record(), original, forward, restored, authority)?;
    actual.revalidate(lock)?;
    completed.validate(authority, original, forward, restored)?;
    Ok(actual.record().clone())
}
pub(crate) fn singleton_restoration_receipt_digest(
    receipt: &crate::profile_auto_unit_policy::linux::RestorationReceipt,
) -> Result<String> {
    let mut bytes = b"aegis-owned-unit-singleton-restoration-v1\0".to_vec();
    bytes.extend_from_slice(&serde_json::to_vec(receipt).map_err(err)?);
    Ok(digest(&bytes))
}
/// Mint only after actual protected rollback admission and actual restored /
/// retired-inode readback. The supplied forward chain remains authenticated.
pub(crate) fn mint_singleton_restoration<
    A: RestorationAuthority,
    C: crate::profile_auto_unit_policy::linux::Context,
>(
    authority: &A,
    context: &C,
    original: &NamespaceRecord,
    history: (&[OwnedTransition], &[OwnedRestoration]),
    receipt: &crate::profile_auto_unit_policy::linux::RestorationReceipt,
    lock: &InstallLock,
) -> Result<OwnedRestoration> {
    use crate::profile_auto_unit_policy::linux as policy;
    policy::verify_restoration(context, receipt)?;
    lock.revalidate()?;
    let epoch = authority.transaction_epoch()?;
    need(context.epoch()? == epoch && receipt.rollback_epoch() == epoch)?;
    let witness = receipt.restored_namespace_witness();
    let role = match witness.role {
        policy::LeafRole::BaseUnit => ManagedRole::BaseUnit,
        policy::LeafRole::Environment => ManagedRole::Environment,
    };
    need(!history.1.iter().any(|r| r.role == role))?;
    let predecessor = history.0.iter().find(|r| r.role == role).ok_or(REFUSED)?;
    need(
        predecessor.receipt_semantics_sha256
            == singleton_receipt_digest(receipt.forward_receipt())?,
    )?;
    let mut expected = authenticated_restored_nodes(original, history.0, history.1, authority)?;
    let manager = current_manager_epoch(original, history.0, authority)?;
    need(observe_manager()? == manager)?;
    let (capture, _, _) = scan(&manager)?;
    let nodes: Vec<_> = capture
        .nodes
        .values()
        .filter(|n| role.contains(&n.path))
        .cloned()
        .collect();
    need(nodes.len() == 1 && nodes[0].path == role.fixed_path())?;
    match (&witness.metadata, witness.sha256) {
        (None, None) => need(
            nodes[0].kind == "missing-file"
                && nodes[0].metadata.is_none()
                && nodes[0].sha256.is_none(),
        )?,
        (Some(m), Some(hash)) => need(
            nodes[0].kind == "regular"
                && nodes[0].metadata.as_ref() == Some(&witness_metadata(m))
                && nodes[0].sha256.as_deref() == Some(hex::encode(hash).as_str()),
        )?,
        _ => return Err(REFUSED),
    }
    restored_role_matches(original, role, &nodes)?;
    expected.retain(|path, _| !role.contains(path));
    for node in &nodes {
        need(expected.insert(node.path.clone(), node.clone()).is_none())?;
    }
    need(runtime_nodes_match(&expected, &capture.nodes) && observe_manager()? == manager)?;
    policy::verify_restoration(context, receipt)?;
    lock.revalidate()?;
    need(authority.transaction_epoch()? == epoch)?;
    let mut record = OwnedRestoration {
        schema: 1,
        role,
        original_namespace: original.generation.clone(),
        epoch,
        forward_generation: predecessor.generation.clone(),
        restoration_receipt_sha256: singleton_restoration_receipt_digest(receipt)?,
        nodes,
        generation: String::new(),
    };
    record.generation = record.compute()?;
    record.validate(original, predecessor, epoch)?;
    Ok(record)
}

pub(crate) fn dropin_restoration_receipt_digest(
    forward: &crate::profile_auto_publication::linux::PublicationReceipt,
    restoration: &crate::profile_auto_unit_policy::linux::DropinRollback,
) -> Result<String> {
    use crate::profile_auto_unit_policy::linux::DropinRollback;
    let mut bytes = b"aegis-owned-unit-dropin-restoration-v1\0".to_vec();
    bytes.extend_from_slice(dropin_receipt_digest(forward)?.as_bytes());
    match restoration {
        DropinRollback::RetainedOriginal(receipt) => {
            bytes.push(1);
            bytes.extend_from_slice(&serde_json::to_vec(receipt.intent()).map_err(err)?);
            bytes.extend_from_slice(&receipt.generation().witness()?);
        }
        DropinRollback::OriginalAbsence(receipt) => {
            bytes.push(2);
            bytes.extend_from_slice(&serde_json::to_vec(receipt.intent()).map_err(err)?);
        }
    }
    Ok(digest(&bytes))
}
pub(crate) fn mint_dropin_restoration<
    A: RestorationAuthority,
    C: crate::profile_auto_unit_policy::linux::DropinContext,
>(
    authority: &A,
    context: &C,
    original: &NamespaceRecord,
    history: (&[OwnedTransition], &[OwnedRestoration]),
    receipts: (
        &crate::profile_auto_publication::linux::PublicationReceipt,
        &crate::profile_auto_unit_policy::linux::DropinRollback,
    ),
    lock: &InstallLock,
) -> Result<OwnedRestoration> {
    use crate::profile_auto_unit_policy::linux as policy;
    policy::verify_dropin_restoration(context, receipts.0, receipts.1)?;
    lock.revalidate()?;
    let epoch = authority.transaction_epoch()?;
    need(context.epoch()? == epoch)?;
    let role = ManagedRole::Dropins;
    need(!history.1.iter().any(|r| r.role == role))?;
    let predecessor = history.0.iter().find(|r| r.role == role).ok_or(REFUSED)?;
    need(predecessor.receipt_semantics_sha256 == dropin_receipt_digest(receipts.0)?)?;
    let mut expected = authenticated_restored_nodes(original, history.0, history.1, authority)?;
    let manager = current_manager_epoch(original, history.0, authority)?;
    need(observe_manager()? == manager)?;
    let (capture, _, _) = scan(&manager)?;
    let nodes: Vec<_> = capture
        .nodes
        .values()
        .filter(|n| role.contains(&n.path))
        .cloned()
        .collect();
    restored_role_matches(original, role, &nodes)?;
    expected.retain(|path, _| !role.contains(path));
    for node in &nodes {
        need(expected.insert(node.path.clone(), node.clone()).is_none())?;
    }
    need(runtime_nodes_match(&expected, &capture.nodes) && observe_manager()? == manager)?;
    policy::verify_dropin_restoration(context, receipts.0, receipts.1)?;
    lock.revalidate()?;
    need(authority.transaction_epoch()? == epoch)?;
    let mut record = OwnedRestoration {
        schema: 1,
        role,
        original_namespace: original.generation.clone(),
        epoch,
        forward_generation: predecessor.generation.clone(),
        restoration_receipt_sha256: dropin_restoration_receipt_digest(receipts.0, receipts.1)?,
        nodes,
        generation: String::new(),
    };
    record.generation = record.compute()?;
    record.validate(original, predecessor, epoch)?;
    Ok(record)
}

/// Final Base publication only: the protected Environment and Dropins records
/// must already exist. This is the sole fresh lazy-load transition constructor,
/// not a relaxation of ordinary partial-publication manager admission.
pub(crate) fn mint_final_base_policy_transition<
    A: crate::profile_auto_stopped_service::CompletePolicyAuthority,
    C: crate::profile_auto_unit_policy::linux::Context,
>(
    authority: &A,
    context: &C,
    original: &NamespaceRecord,
    previous: &[OwnedTransition],
    receipt: &crate::profile_auto_unit_policy::linux::Receipt,
    lock: &InstallLock,
) -> Result<OwnedTransition> {
    use crate::profile_auto_unit_policy::linux as policy;
    policy::verify(context, receipt)?;
    lock.revalidate()?;
    let epoch = authority.transaction_epoch()?;
    need(context.epoch()? == epoch && receipt.publication_epoch() == epoch)?;
    need(
        original.verify_original_singleton(&receipt.original_namespace_witness())?
            == ManagedRole::BaseUnit,
    )?;
    need(
        previous.len() == 2
            && previous.iter().map(|r| r.role).collect::<BTreeSet<_>>()
                == BTreeSet::from([ManagedRole::Environment, ManagedRole::Dropins]),
    )?;
    let mut expected = expected_nodes(original, previous, authority)?;
    let manager = observe_manager()?;
    need(manager.version == original.manager.version && manager.paths == original.manager.paths)?;
    let (capture, unit_files, dropins) = scan(&manager)?;
    let nodes: Vec<_> = capture
        .nodes
        .values()
        .filter(|n| ManagedRole::BaseUnit.contains(&n.path))
        .cloned()
        .collect();
    expected.retain(|path, _| !ManagedRole::BaseUnit.contains(path));
    for node in &nodes {
        need(expected.insert(node.path.clone(), node.clone()).is_none())?;
    }
    need(runtime_nodes_match(&expected, &capture.nodes))?;
    let mut record = OwnedTransition {
        schema: 1,
        role: ManagedRole::BaseUnit,
        original_namespace: original.generation.clone(),
        epoch,
        receipt_semantics_sha256: singleton_receipt_digest(receipt)?,
        original_role_sha256: role_digest(original, ManagedRole::BaseUnit)?,
        nodes,
        generation: String::new(),
    };
    record.generation = record.compute()?;
    record.validate(original, epoch)?;
    let mut all = previous.to_vec();
    all.push(record.clone());
    complete_policy_roles(&all)?;
    authority.authenticate_complete_published_policy(&all)?;
    authority.admit_final_base_publication(&record)?;
    if original.is_absent() {
        expected_loaded_manager(&original.manager, &manager, &unit_files, &dropins)?;
    } else {
        need(manager == original.manager)?;
    }
    let owned: BTreeSet<_> = dropins
        .iter()
        .filter(|p| ManagedRole::Dropins.contains(p))
        .cloned()
        .collect();
    need(owned == authority.expected_dropin_paths()?)?;
    need(observe_manager()? == manager)?;
    policy::verify(context, receipt)?;
    lock.revalidate()?;
    need(authority.transaction_epoch()? == epoch)?;
    Ok(record)
}

fn complete_policy_roles(records: &[OwnedTransition]) -> Result<()> {
    need(
        records.len() == 3
            && records.iter().map(|r| r.role).collect::<BTreeSet<_>>()
                == BTreeSet::from([
                    ManagedRole::BaseUnit,
                    ManagedRole::Environment,
                    ManagedRole::Dropins,
                ]),
    )
}
fn expected_loaded_manager(
    original: &Manager,
    current: &Manager,
    unit_files: &[PathBuf],
    dropins: &[PathBuf],
) -> Result<()> {
    need(
        current.version == original.version
            && current.paths == original.paths
            && current.unit["Id"] == UNIT
            && current.unit["Names"] == UNIT
            && current.unit["LoadState"] == "loaded"
            && current.unit["FragmentPath"] == ManagedRole::BaseUnit.fixed_path().to_string_lossy(),
    )?;
    validate_effective(current, unit_files, dropins)
}
/// Exact owned complete-policy namespace, before an actual checked reload.
/// For captured absence only, a fresh lazy-loaded manager is computed from
/// all three authenticated current role receipts. It is not failure fallback.
pub(crate) struct CompletePolicyPreparation {
    original: NamespaceRecord,
    forward: Vec<OwnedTransition>,
    manager: Manager,
    held: Vec<Held>,
}
impl CompletePolicyPreparation {
    pub(crate) fn is_fresh(&self) -> bool {
        self.original.is_absent()
    }
    pub(crate) fn reopen<A: crate::profile_auto_stopped_service::CompletePolicyAuthority>(
        authority: &A,
        original: &NamespaceRecord,
        forward: &[OwnedTransition],
        lock: &InstallLock,
    ) -> Result<Self> {
        lock.revalidate()?;
        complete_policy_roles(forward)?;
        authority.authenticate_complete_published_policy(forward)?;
        let expected = expected_nodes(original, forward, authority)?;
        let manager = observe_manager()?;
        need(
            manager.version == original.manager.version && manager.paths == original.manager.paths,
        )?;
        let (capture, unit_files, dropins) = scan(&manager)?;
        need(runtime_nodes_match(&expected, &capture.nodes))?;
        let owned: BTreeSet<_> = dropins
            .iter()
            .filter(|p| ManagedRole::Dropins.contains(p))
            .cloned()
            .collect();
        need(owned == authority.expected_dropin_paths()?)?;
        if original.is_absent() {
            expected_loaded_manager(&original.manager, &manager, &unit_files, &dropins)?;
        } else {
            need(manager == original.manager)?;
        }
        need(observe_manager()? == manager)?;
        authority.authenticate_complete_published_policy(forward)?;
        lock.revalidate()?;
        Ok(Self {
            original: original.clone(),
            forward: forward.to_vec(),
            manager,
            held: capture.held,
        })
    }
    pub(crate) fn revalidate<A: crate::profile_auto_stopped_service::CompletePolicyAuthority>(
        &self,
        authority: &A,
        lock: &InstallLock,
    ) -> Result<()> {
        for h in &self.held {
            let regular = h.metadata.mode & libc::S_IFMT == libc::S_IFREG;
            need(metadata(&stat(&h.file)?, regular) == h.metadata)?;
        }
        let again = Self::reopen(authority, &self.original, &self.forward, lock)?;
        need(again.manager == self.manager)?;
        Ok(())
    }
}
/// Called only with non-serializable capability returned by the actual fixed
/// successful owned reload command; no caller status or 'reloaded' boolean.
pub(crate) fn capture_checked_policy_namespace<
    A: crate::profile_auto_stopped_service::CompletePolicyAuthority,
>(
    authority: &A,
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
    completed: &crate::profile_auto_stopped_service::ReloadCompleted,
    lock: &InstallLock,
) -> Result<NamespaceRecord> {
    completed.validate(authority)?;
    lock.revalidate()?;
    complete_policy_roles(forward)?;
    authority.authenticate_complete_published_policy(forward)?;
    let expected = expected_nodes(original, forward, authority)?;
    let manager = observe_manager()?;
    let (capture, unit_files, dropins) = scan(&manager)?;
    let rebound = rebind_runtime_directory_inodes(&expected, &capture.nodes)?;
    completed.validate(authority)?;
    need(capture.nodes == rebound)?;
    expected_loaded_manager(&original.manager, &manager, &unit_files, &dropins)?;
    let owned: BTreeSet<_> = dropins
        .iter()
        .filter(|p| ManagedRole::Dropins.contains(p))
        .cloned()
        .collect();
    need(owned == authority.expected_dropin_paths()?)?;
    need(observe_manager()? == manager)?;
    authority.authenticate_complete_published_policy(forward)?;
    completed.validate(authority)?;
    lock.revalidate()?;
    NamespaceRecord::seal(manager, capture.nodes.into_values().collect())
}

#[cfg(test)]
pub(crate) fn structural_reload_receipt_model(
) -> (NamespaceRecord, Vec<OwnedTransition>, NamespaceRecord) {
    let manager=manager_from(b"Version=255.4\nUnitPath=/etc/systemd/system /usr/lib/systemd/system\n",b"Id=aegis-client.service\nLoadState=not-found\nFragmentPath=\nDropInPaths=\nNames=aegis-client.service\n").unwrap();
    let original = NamespaceRecord::seal(manager.clone(), vec![]).unwrap();
    let records = [
        ManagedRole::BaseUnit,
        ManagedRole::Environment,
        ManagedRole::Dropins,
    ]
    .into_iter()
    .map(|role| OwnedTransition {
        schema: 1,
        role,
        original_namespace: original.generation.clone(),
        epoch: [4; 32],
        receipt_semantics_sha256: "a".repeat(64),
        original_role_sha256: "b".repeat(64),
        nodes: vec![],
        generation: format!(
            "{:064x}",
            match role {
                ManagedRole::BaseUnit => 1u8,
                ManagedRole::Environment => 2u8,
                ManagedRole::Dropins => 3u8,
            }
        ),
    })
    .collect();
    let mut loaded = manager;
    loaded.unit.insert("LoadState".into(), "loaded".into());
    loaded.unit.insert(
        "FragmentPath".into(),
        ManagedRole::BaseUnit
            .fixed_path()
            .to_string_lossy()
            .into_owned(),
    );
    let accepted = NamespaceRecord::seal(loaded, vec![]).unwrap();
    (original, records, accepted)
}

#[cfg(test)]
pub(crate) fn structural_restoration_records_model(
    original: &NamespaceRecord,
    forward: &[OwnedTransition],
) -> Vec<OwnedRestoration> {
    forward
        .iter()
        .map(|record| {
            let mut restored = OwnedRestoration {
                schema: 1,
                role: record.role,
                original_namespace: original.generation.clone(),
                epoch: record.epoch,
                forward_generation: record.generation.clone(),
                restoration_receipt_sha256: "c".repeat(64),
                nodes: vec![],
                generation: String::new(),
            };
            restored.generation = restored.compute().unwrap();
            restored
        })
        .collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn manager(load: &str, fragment: &str, dropins: &str) -> Manager {
        manager_from(b"Version=255.4\nUnitPath=/etc/systemd/system /run/systemd/transient /run/systemd/generator /usr/lib/systemd/system\n",format!("Id=aegis-client.service\nLoadState={load}\nFragmentPath={fragment}\nDropInPaths={dropins}\nNames=aegis-client.service\n").as_bytes()).unwrap()
    }
    #[test]
    fn absent_requires_complete_negative_namespace() {
        let m = manager("not-found", "", "");
        assert!(validate_effective(&m, &[], &[]).is_ok());
        assert!(validate_effective(
            &m,
            &["/run/systemd/transient/aegis-client.service".into()],
            &[]
        )
        .is_err());
    }
    #[test]
    fn vendor_precedence_is_real_search_order() {
        let m = manager("loaded", "/usr/lib/systemd/system/aegis-client.service", "");
        let vendor = PathBuf::from("/usr/lib/systemd/system/aegis-client.service");
        assert!(validate_effective(&m, std::slice::from_ref(&vendor), &[]).is_ok());
        assert!(validate_effective(
            &m,
            &["/etc/systemd/system/aegis-client.service".into(), vendor],
            &[]
        )
        .is_err());
    }
    #[test]
    fn cached_dropin_change_and_shadowing_refuse() {
        let file = PathBuf::from("/etc/systemd/system/aegis-client.service.d/10-policy.conf");
        let m = manager(
            "loaded",
            "/etc/systemd/system/aegis-client.service",
            file.to_str().unwrap(),
        );
        let main = ["/etc/systemd/system/aegis-client.service".into()];
        assert!(validate_effective(&m, &main, std::slice::from_ref(&file)).is_ok());
        assert!(validate_effective(&m, &main, &[]).is_err());
        assert!(validate_effective(
            &m,
            &main,
            &[
                file,
                "/usr/lib/systemd/system/service.d/10-policy.conf".into()
            ]
        )
        .is_err());
    }
    #[test]
    fn aliases_versions_unknown_roots_escape_and_duplicates_refuse() {
        let good=b"Id=aegis-client.service\nLoadState=not-found\nFragmentPath=\nDropInPaths=\nNames=aegis-client.service\n";
        for path in [
            "Version=256\nUnitPath=/etc/systemd/system\n",
            "Version=255\nUnitPath=/tmp/system\n",
            "Version=255\nUnitPath=/etc/systemd/../system\n",
            "Version=255\nUnitPath=/etc/systemd/system /etc/systemd/system\n",
        ] {
            assert!(manager_from(path.as_bytes(), good).is_err());
        }
        assert!(manager_from(b"Version=255\nUnitPath=/etc/systemd/system\n",b"Id=aegis-client.service\nLoadState=loaded\nFragmentPath=\nDropInPaths=\nNames=aegis-client.service alias.service\n").is_err());
    }
    #[test]
    fn explicit_manager_profiles_preserve_namespace_refusals() {
        let good = b"Id=aegis-client.service\nLoadState=not-found\nFragmentPath=\nDropInPaths=\nNames=aegis-client.service\n";
        for version in ["255", "255.4-1ubuntu8.12", "259", "259 (259.5-0ubuntu3.4)"] {
            let paths = format!("Version={version}\nUnitPath=/etc/systemd/system /run/systemd/transient /usr/lib/systemd/system\n");
            let m = manager_from(paths.as_bytes(), good).unwrap();
            assert_eq!(m.version, version);
            for roots in [
                "/tmp/system",
                "/etc/systemd/../system",
                "/etc/systemd/system /etc/systemd/system",
            ] {
                let paths = format!("Version={version}\nUnitPath={roots}\n");
                assert!(manager_from(paths.as_bytes(), good).is_err());
            }
            assert!(manager_from(paths.as_bytes(), b"Id=aegis-client.service\nLoadState=loaded\nFragmentPath=\nDropInPaths=\nNames=aegis-client.service alias.service\n").is_err());
        }
        for version in [
            "", "254", "256", "257", "258", "260", "2590", "v259", " 259", "259\t", "259\r",
            "259\0", "259é",
        ] {
            assert!(!admitted_manager_version(version), "{version:?}");
        }
        assert!(!admitted_manager_version(&format!(
            "259.{}",
            "1".repeat(256)
        )));
    }
    #[test]
    fn opaque_record_tampering_and_unknown_fields_refuse() {
        let m = manager("not-found", "", "");
        let mut r = NamespaceRecord::seal(m, vec![]).unwrap();
        assert!(r.validate().is_ok());
        r.generation = "0".repeat(64);
        assert!(r.validate().is_err());
        let json = serde_json::to_string(&r).unwrap();
        assert!(serde_json::from_str::<NamespaceRecord>(
            &json.replace("\"schema\":1", "\"schema\":1,\"caller_absence\":true")
        )
        .is_err());
    }
    #[test]
    #[ignore = "Actual root-owned tempfile filesystem control; disposable Linux root only"]
    fn real_descriptor_negative_witness_and_alias_refusal() {
        need(
            unsafe { libc::geteuid() } == 0
                && std::env::var("AEGIS_AUTO_DISPOSABLE_CI").as_deref() == Ok("github-hosted"),
        )
        .unwrap();
        let base = PathBuf::from(format!(
            "/run/aegis-unit-ns-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        let mut capture = Capture::new();
        let missing = base.join("absent/deeper");
        assert!(capture.directory(&missing).unwrap().is_none());
        assert_eq!(
            capture.nodes[&base.join("absent")].kind,
            "missing-directory"
        );
        let parent = capture.directory(&base).unwrap().unwrap();
        let file = base.join(UNIT);
        std::fs::write(&file, b"[Service]\nExecStart=/usr/bin/true\n").unwrap();
        assert!(capture.regular(&parent, &file).unwrap());
        std::fs::remove_file(&file).unwrap();
        std::os::unix::fs::symlink("other", &file).unwrap();
        assert!(capture.regular(&parent, &file).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }
    fn disposable_directory(label: &str) -> PathBuf {
        need(
            unsafe { libc::geteuid() } == 0
                && std::env::var("AEGIS_AUTO_DISPOSABLE_CI").as_deref() == Ok("github-hosted"),
        )
        .unwrap();
        let base = PathBuf::from(format!(
            "/run/aegis-unit-ns-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        base
    }
    #[test]
    #[ignore = "Actual descriptor/filesystem fixture, synthetic manager fields; disposable Linux root only"]
    fn real_dropin_change_invalidates_held_generation() {
        let base = disposable_directory("dropin");
        let folder = base.join("aegis-client.service.d");
        std::fs::create_dir(&folder).unwrap();
        let file = folder.join("10-policy.conf");
        std::fs::write(&file, b"[Service]\nUser=root\n").unwrap();
        let mut first = Capture::new();
        assert_eq!(
            first.dropins(&base, "aegis-client.service.d").unwrap(),
            vec![file.clone()]
        );
        let before = first.nodes[&file].clone();
        std::fs::write(&file, b"[Service]\nUser=aegis-svc\n").unwrap();
        let mut after = Capture::new();
        after.dropins(&base, "aegis-client.service.d").unwrap();
        assert_ne!(after.nodes[&file], before);
        let held = first.held.iter().find(|h| h.path == file).unwrap();
        assert_ne!(metadata(&stat(&held.file).unwrap(), true), held.metadata);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    #[ignore = "Real regular file/negative witness fixture; no actual manager or service action"]
    fn real_absent_loaded_file_and_vendor_precedence_fixture() {
        let base = disposable_directory("precedence");
        let local = base.join("local");
        let vendor = base.join("vendor");
        std::fs::create_dir(&local).unwrap();
        std::fs::create_dir(&vendor).unwrap();
        let mut first = Capture::new();
        let localfd = first.directory(&local).unwrap().unwrap();
        assert!(!first.regular(&localfd, &local.join(UNIT)).unwrap());
        let vendorfile = vendor.join(UNIT);
        std::fs::write(&vendorfile, b"[Service]\nExecStart=/usr/bin/true\n").unwrap();
        let vendorfd = first.directory(&vendor).unwrap().unwrap();
        assert!(first.regular(&vendorfd, &vendorfile).unwrap());
        let loaded = manager("loaded", vendorfile.to_str().unwrap(), "");
        assert!(validate_effective(&loaded, std::slice::from_ref(&vendorfile), &[]).is_ok());
        let localfile = local.join(UNIT);
        std::fs::write(&localfile, b"[Service]\nExecStart=/usr/bin/false\n").unwrap();
        let mut next = Capture::new();
        let localfd = next.directory(&local).unwrap().unwrap();
        assert!(next.regular(&localfd, &localfile).unwrap());
        assert!(validate_effective(&loaded, &[localfile, vendorfile], &[]).is_err());
        std::fs::remove_dir_all(base).unwrap();
    }

    fn node(path: &str, kind: &str) -> Node {
        let path = PathBuf::from(path);
        let regular = kind == "regular";
        Node {
            parent: path.parent().unwrap().into(),
            name: path.file_name().unwrap().to_string_lossy().into_owned(),
            path,
            kind: kind.into(),
            metadata: if regular {
                Some(Metadata {
                    device: 1,
                    inode: 2,
                    uid: 0,
                    gid: 0,
                    mode: libc::S_IFREG | 0o644,
                    links: 1,
                    size: 4,
                    mtime_sec: 1,
                    mtime_nsec: 0,
                    ctime_sec: 1,
                    ctime_nsec: 0,
                })
            } else {
                None
            },
            sha256: if regular { Some(digest(b"pure")) } else { None },
        }
    }
    #[test]
    fn completed_reload_rebinds_only_exact_generator_directory_inodes() {
        let mut expected = BTreeMap::new();
        for path in [
            "/run/systemd/generator",
            "/run/systemd/generator.early",
            "/run/systemd/generator.late",
            "/run/systemd/transient",
            "/etc/systemd/system",
        ] {
            let mut directory = node(path, "directory");
            directory.metadata = Some(Metadata {
                device: 1,
                inode: 20,
                uid: 0,
                gid: 0,
                mode: libc::S_IFDIR | 0o755,
                links: 0,
                size: 0,
                mtime_sec: 0,
                mtime_nsec: 0,
                ctime_sec: 0,
                ctime_nsec: 0,
            });
            expected.insert(directory.path.clone(), directory);
        }
        let file = node("/etc/systemd/system/aegis-client.service", "regular");
        expected.insert(file.path.clone(), file);
        let mut actual = expected.clone();
        for path in [
            "/run/systemd/generator",
            "/run/systemd/generator.early",
            "/run/systemd/generator.late",
            "/run/systemd/transient",
        ] {
            actual
                .get_mut(Path::new(path))
                .unwrap()
                .metadata
                .as_mut()
                .unwrap()
                .inode += 1;
        }
        assert_eq!(
            rebind_runtime_directory_inodes(&expected, &actual).unwrap(),
            actual
        );
        let mut wrong = actual.clone();
        wrong
            .get_mut(Path::new("/run/systemd/generator"))
            .unwrap()
            .metadata
            .as_mut()
            .unwrap()
            .mode ^= 0o001;
        assert!(rebind_runtime_directory_inodes(&expected, &wrong).is_err());
        let mut wrong = actual.clone();
        wrong
            .get_mut(Path::new("/etc/systemd/system"))
            .unwrap()
            .metadata
            .as_mut()
            .unwrap()
            .inode += 1;
        assert!(rebind_runtime_directory_inodes(&expected, &wrong).is_err());
        let mut wrong = actual;
        wrong
            .get_mut(Path::new("/etc/systemd/system/aegis-client.service"))
            .unwrap()
            .sha256 = Some("0".repeat(64));
        assert!(rebind_runtime_directory_inodes(&expected, &wrong).is_err());
    }
    #[test]
    fn prepared_namespace_survives_runtime_lookup_directory_recreation() {
        let mut nodes = vec![node("/etc/systemd/system/aegis-client.service", "regular")];
        for path in [
            "/run/systemd/generator",
            "/run/systemd/generator.early",
            "/run/systemd/generator.late",
            "/run/systemd/transient",
        ] {
            let mut directory = node(path, "directory");
            let mut meta = nodes[0].metadata.clone().unwrap();
            meta.mode = libc::S_IFDIR | 0o755;
            meta.links = 0;
            meta.size = 0;
            meta.mtime_sec = 0;
            meta.mtime_nsec = 0;
            meta.ctime_sec = 0;
            meta.ctime_nsec = 0;
            directory.metadata = Some(meta);
            nodes.push(directory);
        }
        let prepared = NamespaceRecord::seal(
            manager("loaded", "/etc/systemd/system/aegis-client.service", ""),
            nodes,
        )
        .unwrap();
        let mut reloaded_nodes = prepared.nodes.clone();
        for node in reloaded_nodes
            .iter_mut()
            .filter(|node| node.kind == "directory")
        {
            node.metadata.as_mut().unwrap().inode += 100;
        }
        let reloaded = NamespaceRecord::seal(prepared.manager.clone(), reloaded_nodes).unwrap();
        assert_ne!(prepared.generation, reloaded.generation);
        assert!(reloaded.matches_namespace_contents(&prepared).is_ok());
        assert!(prepared.matches_namespace_contents(&reloaded).is_ok());
        // Matching is a content check, never rewriting the original sealed
        // record or accepting an unchecked historical generation.
        assert!(prepared.validate().is_ok());
        let mut tampered = reloaded.clone();
        tampered.generation = prepared.generation.clone();
        assert!(tampered.matches_namespace_contents(&prepared).is_err());
        for field in [
            "uid",
            "gid",
            "mode",
            "device",
            "file-inode",
            "file-hash",
            "roster",
            "manager",
        ] {
            let mut changed = reloaded.clone();
            match field {
                "uid" => changed.nodes[1].metadata.as_mut().unwrap().uid += 1,
                "gid" => changed.nodes[1].metadata.as_mut().unwrap().gid += 1,
                "mode" => changed.nodes[1].metadata.as_mut().unwrap().mode ^= 1,
                "device" => changed.nodes[1].metadata.as_mut().unwrap().device += 1,
                "file-inode" => changed.nodes[0].metadata.as_mut().unwrap().inode += 1,
                "file-hash" => changed.nodes[0].sha256 = Some("0".repeat(64)),
                "roster" => {
                    changed.nodes.pop();
                }
                "manager" => {
                    changed.manager.unit.insert(
                        "FragmentPath".into(),
                        "/run/systemd/transient/aegis-client.service".into(),
                    );
                }
                _ => unreachable!(),
            }
            changed = NamespaceRecord::seal(changed.manager, changed.nodes).unwrap();
            assert!(
                changed.matches_namespace_contents(&prepared).is_err(),
                "{field}"
            );
        }
        let mut duplicate = reloaded.clone();
        duplicate.nodes.push(duplicate.nodes[0].clone());
        duplicate = NamespaceRecord::seal(duplicate.manager, duplicate.nodes).unwrap();
        assert!(duplicate.matches_namespace_contents(&prepared).is_err());
    }
    fn transition_model() -> (NamespaceRecord, OwnedTransition) {
        let original = NamespaceRecord::seal(
            manager("not-found", "", ""),
            vec![
                node("/etc/systemd/system/aegis-client.service", "missing-file"),
                node("/etc/default/aegis-client", "missing-file"),
                node(
                    "/usr/lib/systemd/system/aegis-client.service",
                    "missing-file",
                ),
            ],
        )
        .unwrap();
        let mut t = OwnedTransition {
            schema: 1,
            role: ManagedRole::BaseUnit,
            original_namespace: original.generation.clone(),
            epoch: [9; 32],
            receipt_semantics_sha256: "a".repeat(64),
            original_role_sha256: role_digest(&original, ManagedRole::BaseUnit).unwrap(),
            nodes: vec![node("/etc/systemd/system/aegis-client.service", "regular")],
            generation: String::new(),
        };
        t.generation = t.compute().unwrap();
        (original, t)
    }
    #[test]
    fn scoped_transition_keeps_vendor_and_negative_witnesses_exact() {
        let (original, t) = transition_model();
        let expected = scoped_nodes(&original, std::slice::from_ref(&t), [9; 32]).unwrap();
        assert_eq!(
            expected[Path::new("/usr/lib/systemd/system/aegis-client.service")].kind,
            "missing-file"
        );
        assert_eq!(
            expected[Path::new("/etc/default/aegis-client")].kind,
            "missing-file"
        );
        assert_eq!(expected[ManagedRole::BaseUnit.fixed_path()].kind, "regular");
        let mut changed = expected.clone();
        changed.insert(
            PathBuf::from("/usr/lib/systemd/system/aegis-client.service"),
            node("/usr/lib/systemd/system/aegis-client.service", "regular"),
        );
        assert_ne!(changed, expected);
        changed = expected.clone();
        changed.insert(
            PathBuf::from("/etc/systemd/system/other.service"),
            node("/etc/systemd/system/other.service", "regular"),
        );
        assert_ne!(changed, expected);
    }
    #[test]
    fn role_duplicate_foreign_epoch_and_record_tamper_refuse() {
        let (original, t) = transition_model();
        assert!(scoped_nodes(&original, &[t.clone(), t.clone()], [9; 32]).is_err());
        assert!(scoped_nodes(&original, std::slice::from_ref(&t), [8; 32]).is_err());
        let mut forged = t;
        forged.receipt_semantics_sha256 = "b".repeat(64);
        assert!(scoped_nodes(&original, &[forged], [9; 32]).is_err());
    }
    #[test]
    fn out_of_role_and_parent_escape_refuse_even_with_recomputed_digest() {
        let (original, t) = transition_model();
        for path in [
            "/etc/default/aegis-client",
            "/etc/systemd/system/aegis-client.service/../other.service",
        ] {
            let mut forged = t.clone();
            forged.nodes = vec![node(path, "regular")];
            forged.generation = forged.compute().unwrap();
            assert!(scoped_nodes(&original, &[forged], [9; 32]).is_err());
        }
    }

    fn restoration_model() -> (NamespaceRecord, OwnedTransition, OwnedRestoration) {
        let (original, t) = transition_model();
        let mut r = OwnedRestoration {
            schema: 1,
            role: t.role,
            original_namespace: original.generation.clone(),
            epoch: t.epoch,
            forward_generation: t.generation.clone(),
            restoration_receipt_sha256: "d".repeat(64),
            nodes: original
                .nodes
                .iter()
                .filter(|n| t.role.contains(&n.path))
                .cloned()
                .collect(),
            generation: String::new(),
        };
        r.generation = r.compute().unwrap();
        (original, t, r)
    }
    #[test]
    fn restoration_preserves_forward_chain_and_other_negative_witnesses() {
        let (original, t, r) = restoration_model();
        let expected = restored_scoped_nodes(
            &original,
            std::slice::from_ref(&t),
            std::slice::from_ref(&r),
            t.epoch,
        )
        .unwrap();
        assert_eq!(
            expected,
            original
                .nodes
                .iter()
                .cloned()
                .map(|n| (n.path.clone(), n))
                .collect()
        );
        assert!(restored_scoped_nodes(&original, &[], &[r], t.epoch).is_err());
    }
    #[test]
    fn restoration_replay_duplicate_foreign_epoch_and_mutation_refuse() {
        let (original, t, r) = restoration_model();
        assert!(restored_scoped_nodes(
            &original,
            std::slice::from_ref(&t),
            &[r.clone(), r.clone()],
            t.epoch
        )
        .is_err());
        assert!(restored_scoped_nodes(
            &original,
            std::slice::from_ref(&t),
            std::slice::from_ref(&r),
            [8; 32]
        )
        .is_err());
        let mut other = r.clone();
        other.forward_generation = "f".repeat(64);
        other.generation = other.compute().unwrap();
        assert!(
            restored_scoped_nodes(&original, std::slice::from_ref(&t), &[other], t.epoch).is_err()
        );
        let mut tampered = r;
        tampered.restoration_receipt_sha256 = "b".repeat(64);
        assert!(
            restored_scoped_nodes(&original, std::slice::from_ref(&t), &[tampered], t.epoch)
                .is_err()
        );
    }
    #[test]
    fn retained_inode_only_ctime_may_follow_verified_restoration() {
        let mut original = NamespaceRecord::seal(
            manager("loaded", "/etc/systemd/system/aegis-client.service", ""),
            vec![node("/etc/systemd/system/aegis-client.service", "regular")],
        )
        .unwrap();
        let before = original.nodes[0].clone();
        let mut after = before.clone();
        after.metadata.as_mut().unwrap().ctime_sec += 1;
        assert!(restored_role_matches(
            &original,
            ManagedRole::BaseUnit,
            std::slice::from_ref(&after)
        )
        .is_ok());
        for field in [0, 1, 2, 3, 4, 5, 6] {
            let mut wrong = after.clone();
            let m = wrong.metadata.as_mut().unwrap();
            match field {
                0 => m.inode += 1,
                1 => m.uid += 1,
                2 => m.gid += 1,
                3 => m.mode ^= 0o100,
                4 => m.links += 1,
                5 => m.size += 1,
                _ => m.mtime_nsec += 1,
            };
            assert!(restored_role_matches(&original, ManagedRole::BaseUnit, &[wrong]).is_err());
        }
        after.sha256 = Some("0".repeat(64));
        assert!(restored_role_matches(&original, ManagedRole::BaseUnit, &[after]).is_err());
        original.nodes[0].metadata = None;
        assert!(restored_role_matches(&original, ManagedRole::BaseUnit, &[before]).is_err());
    }
    #[test]
    fn restored_absence_and_role_membership_cannot_expand() {
        let (original, t, r) = restoration_model();
        for mut nodes in [
            vec![node("/etc/default/aegis-client", "missing-file")],
            vec![node("/etc/systemd/system/aegis-client.service", "regular")],
            vec![],
        ] {
            let mut bad = r.clone();
            bad.nodes = std::mem::take(&mut nodes);
            bad.generation = bad.compute().unwrap();
            assert!(
                restored_scoped_nodes(&original, std::slice::from_ref(&t), &[bad], t.epoch)
                    .is_err()
            );
        }
    }

    #[test]
    fn dropin_restoration_preserves_entire_original_membership_and_directory_inode() {
        let root = ManagedRole::Dropins.fixed_path();
        let mut directory = node(root.to_str().unwrap(), "directory");
        directory.metadata = Some(Metadata {
            device: 1,
            inode: 40,
            uid: 0,
            gid: 7,
            mode: libc::S_IFDIR | 0o750,
            links: 0,
            size: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        });
        let file = node(
            "/etc/systemd/system/aegis-client.service.d/99-admin.conf",
            "regular",
        );
        let original = NamespaceRecord::seal(
            manager(
                "loaded",
                "/etc/systemd/system/aegis-client.service",
                "/etc/systemd/system/aegis-client.service.d/99-admin.conf",
            ),
            vec![directory.clone(), file.clone()],
        )
        .unwrap();
        assert!(restored_role_matches(
            &original,
            ManagedRole::Dropins,
            &[directory.clone(), file.clone()]
        )
        .is_ok());
        let mut wrong = directory.clone();
        wrong.metadata.as_mut().unwrap().inode += 1;
        assert!(
            restored_role_matches(&original, ManagedRole::Dropins, &[wrong, file.clone()]).is_err()
        );
        assert!(restored_role_matches(
            &original,
            ManagedRole::Dropins,
            std::slice::from_ref(&directory)
        )
        .is_err());
        assert!(restored_role_matches(
            &original,
            ManagedRole::Dropins,
            &[
                directory,
                file,
                node(
                    "/etc/systemd/system/aegis-client.service.d/unknown.conf",
                    "regular"
                )
            ]
        )
        .is_err());
    }

    #[test]
    fn original_singleton_observation_matches_only_exact_sealed_role() {
        use crate::profile_auto_unit_policy::linux as policy;
        let (original, _, _) = restoration_model();
        let mut witness = policy::OriginalNamespaceWitness {
            role: policy::LeafRole::BaseUnit,
            metadata: None,
            sha256: None,
        };
        assert_eq!(
            original.verify_original_singleton(&witness).unwrap(),
            ManagedRole::BaseUnit
        );
        witness.sha256 = Some([1; 32]);
        assert!(original.verify_original_singleton(&witness).is_err());
        witness.sha256 = None;
        let mut other = original.clone();
        other
            .nodes
            .retain(|n| n.path != ManagedRole::BaseUnit.fixed_path());
        other.generation = NamespaceRecord::seal(other.manager.clone(), other.nodes.clone())
            .unwrap()
            .generation;
        assert!(other.verify_original_singleton(&witness).is_err());
        witness.role = policy::LeafRole::Environment;
        assert_eq!(
            original.verify_original_singleton(&witness).unwrap(),
            ManagedRole::Environment
        );
    }

    #[test]
    fn complete_policy_requires_three_distinct_closed_roles() {
        let (original, t) = transition_model();
        let mut records = vec![t.clone(), t.clone(), t.clone()];
        assert!(complete_policy_roles(&records).is_err());
        records[1].role = ManagedRole::Environment;
        records[2].role = ManagedRole::Dropins;
        assert!(complete_policy_roles(&records).is_ok());
        assert!(complete_policy_roles(&records[..2]).is_err());
        records.push(t);
        assert!(complete_policy_roles(&records).is_err());
        assert!(original.is_absent());
    }
    #[test]
    fn prepared_manager_is_computed_from_fixed_precedence_and_exact_dropins() {
        let original = manager("not-found", "", "");
        let path =
            PathBuf::from("/etc/systemd/system/aegis-client.service.d/10-dedicated-uid.conf");
        let loaded = manager(
            "loaded",
            "/etc/systemd/system/aegis-client.service",
            path.to_str().unwrap(),
        );
        let units = vec![
            PathBuf::from("/etc/systemd/system/aegis-client.service"),
            PathBuf::from("/usr/lib/systemd/system/aegis-client.service"),
        ];
        assert!(
            expected_loaded_manager(&original, &loaded, &units, std::slice::from_ref(&path))
                .is_ok()
        );
        assert!(expected_loaded_manager(
            &original,
            &loaded,
            &[
                PathBuf::from("/run/systemd/transient/aegis-client.service"),
                units[0].clone()
            ],
            std::slice::from_ref(&path)
        )
        .is_err());
        assert!(expected_loaded_manager(&original, &loaded, &units, &[]).is_err());
        let mut vendor = loaded.clone();
        vendor.unit.insert(
            "FragmentPath".into(),
            "/usr/lib/systemd/system/aegis-client.service".into(),
        );
        assert!(expected_loaded_manager(&original, &vendor, &units, &[path]).is_err());
    }
    #[test]
    fn checked_manager_transition_refuses_version_roots_alias_and_load_drift() {
        let original = manager("not-found", "", "");
        let loaded = manager("loaded", "/etc/systemd/system/aegis-client.service", "");
        let units = [PathBuf::from("/etc/systemd/system/aegis-client.service")];
        for change in 0..5 {
            let mut wrong = loaded.clone();
            match change {
                0 => wrong.version = "256".into(),
                1 => wrong.paths.swap(0, 1),
                2 => {
                    wrong
                        .unit
                        .insert("Names".into(), "aegis-client.service alias.service".into());
                }
                3 => {
                    wrong.unit.insert("LoadState".into(), "not-found".into());
                }
                _ => {
                    wrong.unit.insert("Id".into(), "other.service".into());
                }
            }
            assert!(expected_loaded_manager(&original, &wrong, &units, &[]).is_err());
        }
    }

    // A fresh boot starts with /run/systemd/transient absent: systemd 255
    // creates it lazily for the first transient unit (for example the scope
    // of the first login session) and only creates generator.early/.late when
    // a generator writes there. These maps are exactly what `scan` records.
    fn lookup_directory(path: &str, device: u64, uid: u32, mode: u32) -> Node {
        let mut directory = node(path, "directory");
        directory.metadata = Some(Metadata {
            device,
            inode: 40,
            uid,
            gid: 0,
            mode,
            links: 0,
            size: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
            ctime_sec: 0,
            ctime_nsec: 0,
        });
        directory
    }
    fn lookup_root_maps(root: &str) -> (BTreeMap<PathBuf, Node>, BTreeMap<PathBuf, Node>) {
        let mut absent = BTreeMap::new();
        for path in ["/run", "/run/systemd"] {
            let directory = lookup_directory(path, 7, 0, libc::S_IFDIR | 0o755);
            absent.insert(directory.path.clone(), directory);
        }
        let file = node("/etc/systemd/system/aegis-client.service", "regular");
        absent.insert(file.path.clone(), file);
        let missing = node(root, "missing-directory");
        absent.insert(missing.path.clone(), missing);
        let mut present = absent.clone();
        let directory = lookup_directory(root, 7, 0, libc::S_IFDIR | 0o755);
        present.insert(directory.path.clone(), directory);
        let unit = node(&format!("{root}/{UNIT}"), "missing-file");
        present.insert(unit.path.clone(), unit);
        for kind in DROPINS {
            let folder = node(&format!("{root}/{kind}"), "missing-directory");
            present.insert(folder.path.clone(), folder);
        }
        (absent, present)
    }
    #[test]
    fn empty_runtime_lookup_root_presence_is_not_a_namespace_change() {
        for root in [
            "/run/systemd/transient",
            "/run/systemd/generator",
            "/run/systemd/generator.early",
            "/run/systemd/generator.late",
        ] {
            let (absent, present) = lookup_root_maps(root);
            // First transient unit after a cold boot: absent -> empty root.
            assert_eq!(
                rebind_runtime_directory_inodes(&absent, &present).unwrap(),
                present,
                "{root}"
            );
            // A record sealed while the root existed, read after a reboot.
            assert_eq!(
                rebind_runtime_directory_inodes(&present, &absent).unwrap(),
                absent,
                "{root}"
            );
            assert!(runtime_nodes_match(&absent, &present), "{root}");
            let loaded = manager("loaded", "/etc/systemd/system/aegis-client.service", "");
            let before =
                NamespaceRecord::seal(loaded.clone(), absent.values().cloned().collect()).unwrap();
            let after = NamespaceRecord::seal(loaded, present.values().cloned().collect()).unwrap();
            assert!(after.matches_namespace_contents(&before).is_ok(), "{root}");
            assert!(before.matches_namespace_contents(&after).is_ok(), "{root}");
        }
    }
    #[test]
    fn runtime_lookup_root_presence_keeps_unit_and_dropin_refusals() {
        let root = "/run/systemd/transient";
        let (absent, present) = lookup_root_maps(root);
        let mut refusals: Vec<(&str, BTreeMap<PathBuf, Node>)> = Vec::new();
        let mut unit = present.clone();
        let file = node(&format!("{root}/{UNIT}"), "regular");
        unit.insert(file.path.clone(), file);
        refusals.push(("transient unit file", unit));
        for kind in DROPINS {
            let mut dropin = present.clone();
            let folder = lookup_directory(&format!("{root}/{kind}"), 7, 0, libc::S_IFDIR | 0o755);
            dropin.insert(folder.path.clone(), folder);
            let file = node(&format!("{root}/{kind}/10-policy.conf"), "regular");
            dropin.insert(file.path.clone(), file);
            refusals.push(("transient drop-in", dropin));
        }
        let mut incomplete = present.clone();
        incomplete.remove(Path::new(&format!("{root}/aegis-.service.d")));
        refusals.push(("incomplete negative witness", incomplete));
        let mut extra = present.clone();
        let other = node(&format!("{root}/other.service"), "missing-file");
        extra.insert(other.path.clone(), other);
        refusals.push(("foreign descendant witness", extra));
        for (label, uid, mode, device) in [
            ("non-root owner", 1000, libc::S_IFDIR | 0o755, 7),
            ("writable mode", 0, libc::S_IFDIR | 0o777, 7),
            ("other device", 0, libc::S_IFDIR | 0o755, 8),
        ] {
            let mut changed = present.clone();
            let directory = lookup_directory(root, device, uid, mode);
            changed.insert(directory.path.clone(), directory);
            refusals.push((label, changed));
        }
        let mut file_changed = present.clone();
        file_changed
            .get_mut(Path::new("/etc/systemd/system/aegis-client.service"))
            .unwrap()
            .sha256 = Some("0".repeat(64));
        refusals.push(("unit file hash beside presence change", file_changed));
        for (label, changed) in &refusals {
            assert!(
                rebind_runtime_directory_inodes(&absent, changed).is_err(),
                "absent -> {label}"
            );
            assert!(
                rebind_runtime_directory_inodes(changed, &absent).is_err(),
                "{label} -> absent"
            );
        }
        // Only PID1's four runtime lookup roots may change presence.
        for path in ["/run/systemd/system", "/run/systemd/system.control"] {
            let (absent, present) = lookup_root_maps(path);
            assert!(
                rebind_runtime_directory_inodes(&absent, &present).is_err(),
                "{path}"
            );
            assert!(
                rebind_runtime_directory_inodes(&present, &absent).is_err(),
                "{path}"
            );
        }
    }
    #[test]
    fn reload_accepted_runtime_root_presence_reaches_restoration_chain() {
        let root = "/run/systemd/transient";
        let (absent, present) = lookup_root_maps(root);
        // Prepare captured before the boot's first login; the accepted reload
        // namespace after it. Restoration must expect the accepted subtree.
        let mut restored = absent.clone();
        let restored_unit = node("/etc/systemd/system/aegis-client.service", "missing-file");
        restored.insert(restored_unit.path.clone(), restored_unit.clone());
        let rebound = rebind_runtime_directory_inodes(&absent, &present).unwrap();
        let mut expected = restored.clone();
        carry_accepted_runtime_roots(&mut expected, &absent, &rebound).unwrap();
        let mut current = present.clone();
        current.insert(restored_unit.path.clone(), restored_unit);
        assert_eq!(expected, current);
        assert!(runtime_nodes_match(&expected, &current));
        // An accepted inode-only replacement is still carried exactly.
        let mut moved = present.clone();
        moved
            .get_mut(Path::new(root))
            .unwrap()
            .metadata
            .as_mut()
            .unwrap()
            .inode += 9;
        let rebound = rebind_runtime_directory_inodes(&present, &moved).unwrap();
        let mut expected = present.clone();
        carry_accepted_runtime_roots(&mut expected, &present, &rebound).unwrap();
        assert_eq!(expected, moved);
        // The chain's runtime subtree must be the forward view it was proved from.
        let mut diverged = restored.clone();
        diverged.remove(Path::new(root));
        assert!(carry_accepted_runtime_roots(&mut diverged, &absent, &rebound).is_err());
        let mut foreign = present.clone();
        let other = node(&format!("{root}/other.service"), "missing-file");
        foreign.insert(other.path.clone(), other);
        assert!(carry_accepted_runtime_roots(&mut foreign, &present, &rebound).is_err());
    }
    #[test]
    #[ignore = "Only on an isolated real Linux systemd PID1 fixture; starts one transient scope"]
    fn real_pid1_first_transient_unit_keeps_fixed_unit_namespace() {
        use std::process::Command;
        assert_eq!(
            std::env::var("AEGIS_TEST_PID1_TRANSIENT_ROOT").as_deref(),
            Ok("1")
        );
        assert_eq!(unsafe { libc::geteuid() }, 0);
        assert_eq!(
            std::fs::read_to_string("/proc/1/comm").unwrap(),
            "systemd\n"
        );
        let transient = Path::new("/run/systemd/transient");
        // Fresh-boot precondition: PID1 has not created any transient unit.
        assert!(std::fs::symlink_metadata(transient).is_err());
        let lock = InstallLock::acquire().unwrap();
        let boot = UnitNamespaceSnapshot::capture(&lock).unwrap();
        assert_eq!(
            boot.record
                .nodes
                .iter()
                .find(|n| n.path == transient)
                .unwrap()
                .kind,
            "missing-directory"
        );
        let scope = Command::new("/usr/bin/systemd-run")
            .args([
                "--scope",
                "--quiet",
                "--unit=aegis-ns-first-transient",
                "/bin/true",
            ])
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin")
            .status()
            .unwrap();
        assert!(scope.success());
        assert!(std::fs::symlink_metadata(transient).unwrap().is_dir());
        // The cold-boot observer's later revalidation must not treat PID1's
        // lazily created, empty lookup root as a changed unit namespace.
        boot.revalidate(&lock).unwrap();
        let session = UnitNamespaceSnapshot::capture(&lock).unwrap();
        // A real transient drop-in directory for the fixed unit still changes it.
        let dropin = transient.join("aegis-client.service.d");
        std::fs::create_dir(&dropin).unwrap();
        let refused = boot.revalidate(&lock).is_err() && session.revalidate(&lock).is_err();
        std::fs::remove_dir(&dropin).unwrap();
        assert!(refused);
        // A record observed while the root existed, read when it is absent
        // again (the next boot before its first login), is still the same.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::fs::read_dir(transient).unwrap().next().is_some() {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        std::fs::remove_dir(transient).unwrap();
        session.revalidate(&lock).unwrap();
        UnitNamespaceSnapshot::reopen(session.record(), &lock)
            .unwrap()
            .revalidate(&lock)
            .unwrap();
    }
}
