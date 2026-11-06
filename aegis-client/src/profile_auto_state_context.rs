//! PRIVATE UNAPPLIED: concrete protected AUTO state context, nested in transaction.
//! No original secret pathname reads, arbitrary public JSON authority or fake receipts.
use super::{authority::StageGuard, digest, Phase};
use crate::profile_auto_capture::{
    self as capture, GenerationGuard, GenerationRecord, InputRole, SealedStageAuthority,
};
use crate::profile_auto_state_publication::{
    self as publish, DestinationAnchor, DestinationDisposition, NodeIdentity, PublishOutcome,
    StateAuthority, StateReceipt, VerifiedStateBytes,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    cell::RefCell,
    ffi::CString,
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
};
use zeroize::Zeroizing;
const PRIOR: &str = "input/prior-state/bytes";
const RAW: &str = "input/payload/state/state.json";
const ACCEPTED: &str = "accepted/payload/state/state.json";
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "Protected AUTO state authority refused",
    )
}
fn convert<T>(r: super::Result<T>) -> io::Result<T> {
    r.map_err(|_| invalid())
}
/// Only authenticated, resolved outcomes may permit the enclosing rollback phase.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StateRecovery {
    NoPending,
    Resolved,
}
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum StateRollback {
    NoActionProven,
    RetiredOwned,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
enum Event {
    RetirementContainerIntent {
        parent_path: PathBuf,
        parent: NodeIdentity,
        name: String,
    },
    RetirementContainerCreated {
        parent_path: PathBuf,
        parent: NodeIdentity,
        name: String,
        node: NodeIdentity,
    },
    DirectoryIntent {
        parent: NodeIdentity,
        name: String,
        uid: u32,
        gid: u32,
        mode: u32,
    },
    DirectoryCreated {
        parent: NodeIdentity,
        name: String,
        node: NodeIdentity,
    },
    PublishIntent(StateReceipt),
    Created(StateReceipt),
    ExistingUnowned {
        parent: NodeIdentity,
        file: NodeIdentity,
    },
    Skipped,
    PublishNotLinked,
    RecoveryRequired,
    RetirementIntent {
        receipt: StateReceipt,
        name: String,
    },
    Retired {
        receipt: StateReceipt,
        name: String,
        node: NodeIdentity,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    schema: u32,
    nonce: String,
    input: String,
    planned: String,
    mode: String,
    uid: u32,
    gid: u32,
    target: PathBuf,
    ordinal: usize,
    predecessor: Option<String>,
    event: Event,
}
/// Read-only private metadata/bytes maps are fixed at admission; all durable
/// phase and receipt updates use the REAL StageGuard Header/Store through this cell.
pub(super) struct StateContext<'a> {
    stage: &'a RefCell<StageGuard>,
    original: GenerationRecord,
    old_uid: u32,
    uid: u32,
    gid: u32,
    target: PathBuf,
    nonce: String,
    input: String,
    planned: String,
    mode: String,
    prior: Option<Zeroizing<Vec<u8>>>,
    prior_hash: Option<String>,
    raw_existing: bool,
    prior_original: Option<GenerationRecord>,
    initial: RefCell<Option<GenerationGuard>>,
    anchor: RefCell<Option<(NodeIdentity, Vec<String>, usize)>>,
}
fn node(f: &File) -> io::Result<NodeIdentity> {
    let m = f.metadata()?;
    Ok(NodeIdentity {
        dev: m.dev(),
        ino: m.ino(),
        mode: m.mode(),
        uid: m.uid(),
        gid: m.gid(),
        links: m.nlink(),
        len: m.len(),
        modified: (m.mtime(), m.mtime_nsec()),
        changed: (m.ctime(), m.ctime_nsec()),
    })
}
fn static_dir(a: &NodeIdentity, b: &NodeIdentity) -> bool {
    a.dev == b.dev && a.ino == b.ino && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid
}
fn linked(i: &StateReceipt, r: &StateReceipt) -> bool {
    static_dir(&i.parent, &r.parent)
        && i.private_sha256 == r.private_sha256
        && i.file.dev == r.file.dev
        && i.file.ino == r.file.ino
        && i.file.mode == r.file.mode
        && i.file.uid == r.file.uid
        && i.file.gid == r.file.gid
        && i.file.len == r.file.len
        && i.file.modified == r.file.modified
        && i.file.links == 0
        && r.file.links == 1
}
fn raw_open(parent: &File, name: &str, flags: i32) -> io::Result<File> {
    let n = CString::new(name).map_err(|_| invalid())?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            n.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn regular(n: &NodeIdentity, uids: &[u32]) -> bool {
    n.mode & libc::S_IFMT == libc::S_IFREG
        && n.links == 1
        && n.len <= 16 * 1024 * 1024
        && n.mode & 0o077 == 0
        && uids.contains(&n.uid)
}
fn traversable(n: &NodeIdentity, uid: u32, gid: u32) -> bool {
    uid == 0
        || n.mode
            & (if n.uid == uid {
                0o100
            } else if n.gid == gid {
                0o010
            } else {
                0o001
            })
            != 0
}
fn state_writer_ready(n: &NodeIdentity, uid: u32, gid: u32) -> bool {
    if uid == 0 {
        return true;
    }
    let required = if n.uid == uid {
        0o300
    } else if n.gid == gid {
        0o030
    } else {
        0o003
    };
    n.mode & required == required
}
fn open_absolute_state_dir(path: &Path, uid: u32, gid: u32) -> io::Result<File> {
    if !path.is_absolute()
        || path
            .components()
            .any(|p| !matches!(p, Component::RootDir | Component::Normal(_)))
    {
        return Err(invalid());
    }
    let slash = CString::new("/").map_err(|_| invalid())?;
    let fd = unsafe {
        libc::open(
            slash.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut held = unsafe { File::from_raw_fd(fd) };
    for part in path.components() {
        if let Component::Normal(name) = part {
            let text = name.to_str().ok_or_else(invalid)?;
            held = raw_open(&held, text, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let n = node(&held)?;
            if (n.mode & 0o022 != 0 && !(n.uid == 0 && n.mode & libc::S_ISVTX != 0))
                || ![0, uid].contains(&n.uid)
                || !traversable(&n, uid, gid)
            {
                return Err(invalid());
            }
        }
    }
    Ok(held)
}

/// Reopen only a previously admitted regular O_PATH inode through verified held
/// kernel procfs. Keep the held parent and named leaf bound to that inode before
/// and after the read; ctime alone cannot prove the leaf was not relocated.
/// Never perform a second pathname byte read after an inode check.
fn read_owned_fd(
    parent: &File,
    pinned: &File,
    receipt: &StateReceipt,
) -> io::Result<Zeroizing<Vec<u8>>> {
    use std::io::Read;
    let named_owned = || -> io::Result<bool> {
        if !static_dir(&node(parent)?, &receipt.parent) {
            return Ok(false);
        }
        let named = raw_open(parent, "state.json", libc::O_PATH | libc::O_NONBLOCK)?;
        Ok(node(&named)? == receipt.file && node(pinned)? == receipt.file)
    };
    if !named_owned()? || !regular(&receipt.file, &[0, receipt.file.uid]) {
        return Err(invalid());
    }
    let name = CString::new("/proc").map_err(|_| invalid())?;
    let raw = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let proc = unsafe { File::from_raw_fd(raw) };
    let n = node(&proc)?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if n.uid != 0
        || n.mode & 0o022 != 0
        || unsafe { libc::fstatfs(proc.as_raw_fd(), fs.as_mut_ptr()) } != 0
        || unsafe { fs.assume_init() }.f_type != 0x9fa0
    {
        return Err(invalid());
    }
    let this = CString::new("self").map_err(|_| invalid())?;
    let raw = unsafe {
        libc::openat(
            proc.as_raw_fd(),
            this.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let current = unsafe { File::from_raw_fd(raw) };
    let descriptor_root = raw_open(&current, "fd", libc::O_RDONLY | libc::O_DIRECTORY)?;
    let mut fs = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(descriptor_root.as_raw_fd(), fs.as_mut_ptr()) } != 0
        || unsafe { fs.assume_init() }.f_type != 0x9fa0
    {
        return Err(invalid());
    }
    let number = CString::new(pinned.as_raw_fd().to_string()).map_err(|_| invalid())?;
    let raw = unsafe {
        libc::openat(
            descriptor_root.as_raw_fd(),
            number.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NONBLOCK,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut reader = unsafe { File::from_raw_fd(raw) };
    if node(&reader)? != receipt.file {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .by_ref()
        .take(16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)?;
    let hash: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    if bytes.len() as u64 != receipt.file.len
        || hash != receipt.private_sha256
        || node(&reader)? != receipt.file
        || !named_owned()?
    {
        return Err(invalid());
    }
    Ok(bytes)
}

impl<'a> StateContext<'a> {
    pub(super) fn new(stage: &'a RefCell<StageGuard>) -> io::Result<Self> {
        let g = stage.try_borrow().map_err(|_| invalid())?;
        SealedStageAuthority::revalidate(&*g)?;
        if !matches!(
            g.header.phase,
            Phase::Custody
                | Phase::State
                | Phase::Config
                | Phase::Metadata
                | Phase::Finalized
                | Phase::NativeRecoveryRequired
        ) || g.header.pending.is_some()
        {
            return Err(invalid());
        }
        let uid = g.header.service_uid.ok_or_else(invalid)?;
        let gid = g.header.service_gid.ok_or_else(invalid)?;
        let src = g
            .manifest
            .sources
            .iter()
            .find(|s| s.role == "state")
            .ok_or_else(invalid)?;
        let raw = convert(g.store.read(&src.generation_leaf))?;
        if g.header.leaves.get(&src.generation_leaf) != Some(&digest(&raw)) {
            return Err(invalid());
        }
        let original: GenerationRecord = serde_json::from_slice(&raw).map_err(|_| invalid())?;
        if original.original_source() != g.header.state_dir
            || !matches!(original.kind(), 0 | 2)
            || !matches!(original.role(),InputRole::ServiceInput{service_uid,administrator_uid:0} if service_uid==g.manifest.service_uid)
        {
            return Err(invalid());
        }
        let raw_existing = g.header.leaves.contains_key(Path::new(RAW));
        let accepted = g.header.leaves.get(Path::new(ACCEPTED));
        let (prior, prior_hash, prior_original) = if raw_existing {
            if accepted != g.header.leaves.get(Path::new(RAW)) {
                return Err(invalid());
            }
            (None, None, None)
        } else if let Some(expected) = accepted {
            let prior_source = g
                .manifest
                .sources
                .iter()
                .find(|s| s.role == "prior-state")
                .ok_or_else(invalid)?;
            let generation = convert(g.store.read(&prior_source.generation_leaf))?;
            if g.header.leaves.get(&prior_source.generation_leaf) != Some(&digest(&generation)) {
                return Err(invalid());
            }
            let record: GenerationRecord =
                serde_json::from_slice(&generation).map_err(|_| invalid())?;
            if record.kind() != 1
                || record.original_source() != prior_source.original_path
                || record.original_source() == g.header.state_dir.join("state.json")
                || !matches!(record.role(),InputRole::ServiceInput{service_uid,administrator_uid:0} if service_uid==g.manifest.service_uid)
            {
                return Err(invalid());
            }
            let bytes = convert(g.store.read(Path::new(PRIOR)))?;
            if g.header.leaves.get(Path::new(PRIOR)) != Some(expected)
                || digest(&bytes) != *expected
            {
                return Err(invalid());
            }
            let final_bytes = convert(g.store.read(Path::new(ACCEPTED)))?;
            if *bytes != *final_bytes {
                return Err(invalid());
            }
            (Some(bytes), Some(expected.clone()), Some(record))
        } else {
            (None, None, None)
        };
        let context = Self {
            stage,
            original,
            old_uid: g.manifest.service_uid,
            uid,
            gid,
            target: g.header.state_dir.clone(),
            nonce: g.header.transaction_nonce.clone(),
            input: g.header.input_generation.clone(),
            planned: g.header.planned_generation.clone(),
            mode: g.header.mode.name().into(),
            prior,
            prior_hash,
            prior_original,
            raw_existing,
            initial: RefCell::new(None),
            anchor: RefCell::new(None),
        };
        drop(g);
        context.verify()?;
        Ok(context)
    }
    fn protected(&self, g: &StageGuard) -> io::Result<()> {
        SealedStageAuthority::revalidate(g)?;
        if g.header.transaction_nonce != self.nonce
            || g.header.input_generation != self.input
            || g.header.planned_generation != self.planned
            || g.header.mode.name() != self.mode
            || g.header.state_dir != self.target
            || g.header.service_uid != Some(self.uid)
            || g.header.service_gid != Some(self.gid)
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn logs_from(&self, g: &StageGuard) -> io::Result<Vec<Envelope>> {
        self.protected(g)?;
        let mut out = Vec::new();
        let mut predecessor = None;
        for (ordinal, (leaf, sha)) in g.header.state_records.iter().enumerate() {
            if leaf.as_path() != Path::new(&format!("receipts/state/{ordinal:04}.json")) {
                return Err(invalid());
            }
            let bytes = convert(g.store.read(leaf))?;
            if digest(&bytes) != *sha {
                return Err(invalid());
            }
            let r: Envelope = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            if r.schema != 1
                || r.nonce != self.nonce
                || r.input != self.input
                || r.planned != self.planned
                || r.mode != self.mode
                || r.uid != self.uid
                || r.gid != self.gid
                || r.target != self.target
                || r.ordinal != ordinal
                || r.predecessor != predecessor
            {
                return Err(invalid());
            }
            predecessor = Some(sha.clone());
            out.push(r);
        }
        Ok(out)
    }
    fn logs(&self) -> io::Result<Vec<Envelope>> {
        let g = self.stage.try_borrow().map_err(|_| invalid())?;
        self.logs_from(&g)
    }
    fn verify(&self) -> io::Result<()> {
        let _ = self.logs()?;
        Ok(())
    }
    fn append(&self, event: Event) -> io::Result<()> {
        let mut g = self.stage.try_borrow_mut().map_err(|_| invalid())?;
        let previous = self.logs_from(&g)?;
        if previous.len() >= 128 {
            return Err(invalid());
        }
        let ordinal = previous.len();
        let leaf = PathBuf::from(format!("receipts/state/{ordinal:04}.json"));
        let envelope = Envelope {
            schema: 1,
            nonce: self.nonce.clone(),
            input: self.input.clone(),
            planned: self.planned.clone(),
            mode: self.mode.clone(),
            uid: self.uid,
            gid: self.gid,
            target: self.target.clone(),
            ordinal,
            predecessor: g.header.state_records.values().last().cloned(),
            event,
        };
        let bytes = serde_json::to_vec(&envelope).map_err(|_| invalid())?;
        convert(g.store.write_new(&leaf, &bytes))?;
        g.header.state_records.insert(leaf, digest(&bytes));
        convert(g.persist_header())
    }
    fn phase(&self, phase: Phase) -> io::Result<()> {
        let g = self.stage.try_borrow().map_err(|_| invalid())?;
        self.protected(&g)?;
        if g.header.phase != phase || g.header.capture_started {
            return Err(invalid());
        }
        Ok(())
    }
    fn advance_state(&self) -> io::Result<()> {
        let mut g = self.stage.try_borrow_mut().map_err(|_| invalid())?;
        self.protected(&g)?;
        if g.header.phase != Phase::Custody {
            return Err(invalid());
        }
        g.header.phase = Phase::State;
        convert(g.persist_header())
    }
    /// Held no-follow target ancestry. Missing components are bounded and returned
    /// without creating anything; after own creation the exact recorded dir inode
    /// chain must match instead of re-opening obsolete original absence metadata.
    fn target_anchor(&self) -> io::Result<DestinationAnchor> {
        self.verify()?;
        let slash = CString::new("/").map_err(|_| invalid())?;
        let fd = unsafe {
            libc::open(
                slash.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut held = unsafe { File::from_raw_fd(fd) };
        let parts: Vec<_> = self
            .target
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => n.to_str().map(str::to_owned),
                _ => None,
            })
            .collect();
        if parts.is_empty() {
            return Err(invalid());
        }
        let records = self.logs()?;
        let created: Vec<_> = records
            .iter()
            .filter_map(|r| match &r.event {
                Event::DirectoryCreated { parent, name, node } => Some((parent, name, node)),
                _ => None,
            })
            .collect();
        for (index, part) in parts.iter().enumerate() {
            let before = node(&held)?;
            if before.mode & libc::S_IFMT != libc::S_IFDIR
                || (before.mode & 0o022 != 0
                    && !(before.uid == 0 && before.mode & libc::S_ISVTX != 0))
                || (![0, self.uid, self.old_uid].contains(&before.uid))
                || !traversable(&before, self.uid, self.gid)
            {
                return Err(invalid());
            }
            match raw_open(&held, part, libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(child) => {
                    let n = node(&child)?;
                    if n.mode & libc::S_IFMT != libc::S_IFDIR
                        || (n.mode & 0o022 != 0
                            && !(index + 1 < parts.len()
                                && n.uid == 0
                                && n.mode & libc::S_ISVTX != 0))
                        || (![0, self.uid, self.old_uid].contains(&n.uid))
                        || !traversable(&n, self.uid, self.gid)
                    {
                        return Err(invalid());
                    }
                    for (p, name, c) in &created {
                        if static_dir(p, &before) && *name == part && !static_dir(c, &n) {
                            return Err(invalid());
                        }
                    }
                    held = child;
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    let suffix = parts[index..].to_vec();
                    if suffix.len() > 8 {
                        return Err(invalid());
                    }
                    return DestinationAnchor::new(held, suffix);
                }
                Err(e) => return Err(e),
            }
        }
        DestinationAnchor::new(held, Vec::new())
    }
    fn named_state(&self, parent: &File) -> io::Result<(File, NodeIdentity)> {
        let fd = raw_open(parent, "state.json", libc::O_PATH | libc::O_NONBLOCK)?;
        let n = node(&fd)?;
        if !regular(&n, &[0, self.old_uid, self.uid]) {
            return Err(invalid());
        }
        Ok((fd, n))
    }
    fn require_custody_proof(&self) -> io::Result<()> {
        let g = self.stage.try_borrow().map_err(|_| invalid())?;
        self.protected(&g)?;
        let leaf = g.header.active_records.get("config").ok_or_else(invalid)?;
        let seal = g.header.current_records.get(leaf).ok_or_else(invalid)?;
        if seal.phase != "custody" || seal.role != "config" {
            return Err(invalid());
        }
        let admitted = convert(g.publication_record("config"))?;
        let target = crate::profile_auto_publication::linux::Target::open(&g.header.config_root)
            .map_err(|_| invalid())?;
        let _owned = crate::profile_auto_publication::linux::reopen_own_receipt(&target, &admitted)
            .map_err(|_| invalid())?;
        Ok(())
    }
    fn validate_prior_generation(&self) -> io::Result<()> {
        let Some(record) = &self.prior_original else {
            return Ok(());
        };
        let g = self.stage.try_borrow().map_err(|_| invalid())?;
        self.protected(&g)?;
        if let Ok(relative) = record.original_source().strip_prefix(&g.header.config_root) {
            if relative.as_os_str().is_empty()
                || g.header
                    .leaves
                    .get(&Path::new("input/payload/config").join(relative))
                    != self.prior_hash.as_ref()
            {
                return Err(invalid());
            }
            drop(g);
            self.require_custody_proof()
        } else {
            drop(g);
            let held = capture::reopen_generation(record)?;
            held.revalidate()
        }
    }
    fn newest_created(&self) -> io::Result<StateReceipt> {
        self.logs()?
            .into_iter()
            .rev()
            .find_map(|r| match r.event {
                Event::Created(c) => Some(c),
                _ => None,
            })
            .ok_or_else(invalid)
    }
    /// Same-filesystem root-private retirement namespace outside the selected
    /// state input tree. /run Store is NEVER used as an unsafe cross-device fallback.
    fn retirement_container(&self) -> io::Result<File> {
        self.verify()?;
        let wanted = self.target.parent().ok_or_else(invalid)?;
        let parts: Vec<_> = wanted
            .components()
            .filter_map(|c| match c {
                Component::Normal(n) => n.to_str().map(str::to_owned),
                _ => None,
            })
            .collect();
        let slash = CString::new("/").map_err(|_| invalid())?;
        let raw = unsafe {
            libc::open(
                slash.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut held = unsafe { File::from_raw_fd(raw) };
        let mut parent_path = PathBuf::from("/");
        for part in parts {
            match raw_open(&held, &part, libc::O_RDONLY | libc::O_DIRECTORY) {
                Ok(child) => {
                    held = child;
                    parent_path.push(&part);
                }
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => break,
                Err(e) => return Err(e),
            }
        }
        let parent = node(&held)?;
        if parent.uid != 0 || parent.mode & 0o022 != 0 {
            return Err(invalid());
        }
        let name = format!(".aegis-state-retirement-{}", self.nonce);
        let records = self.logs()?;
        if let Some((path, p, n, c)) = records.iter().rev().find_map(|r| match &r.event {
            Event::RetirementContainerCreated {
                parent_path,
                parent,
                name,
                node,
            } => Some((parent_path, parent, name, node)),
            _ => None,
        }) {
            if !wanted.starts_with(path) || *n != name {
                return Err(invalid());
            }
            let admitted_parent = open_absolute_state_dir(path, 0, 0)?;
            if !static_dir(p, &node(&admitted_parent)?) {
                return Err(invalid());
            }
            let child = raw_open(&admitted_parent, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
            let actual = node(&child)?;
            if !static_dir(c, &actual) || actual.uid != 0 || actual.mode & 0o777 != 0o700 {
                return Err(invalid());
            }
            return Ok(child);
        }
        self.phase(Phase::Custody)?;
        if records
            .iter()
            .any(|r| matches!(r.event, Event::RetirementContainerIntent { .. }))
        {
            return Err(invalid());
        }
        match raw_open(&held, &name, libc::O_PATH | libc::O_NONBLOCK) {
            Ok(_) => return Err(invalid()),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return Err(e),
        }
        self.append(Event::RetirementContainerIntent {
            parent_path: parent_path.clone(),
            parent: parent.clone(),
            name: name.clone(),
        })?;
        let c = CString::new(name.as_str()).map_err(|_| invalid())?;
        if unsafe { libc::mkdirat(held.as_raw_fd(), c.as_ptr(), 0o700) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let child = raw_open(&held, &name, libc::O_RDONLY | libc::O_DIRECTORY)?;
        let initial = node(&child)?;
        if initial.uid != 0 || initial.mode & 0o777 != 0o700 {
            return Err(invalid());
        }
        if unsafe { libc::fchown(child.as_raw_fd(), 0, 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let actual = node(&child)?;
        if initial.dev != actual.dev
            || initial.ino != actual.ino
            || actual.uid != 0
            || actual.gid != 0
            || actual.mode & 0o777 != 0o700
        {
            return Err(invalid());
        }
        child.sync_all()?;
        held.sync_all()?;
        self.append(Event::RetirementContainerCreated {
            parent_path,
            parent,
            name,
            node: actual,
        })?;
        Ok(child)
    }
    pub(super) fn commit_state(&self) -> io::Result<()> {
        self.phase(Phase::Custody)?;
        self.require_custody_proof()?;
        let logs = self.logs()?;
        if logs.last().is_some_and(|r| {
            matches!(
                r.event,
                Event::PublishIntent(_)
                    | Event::DirectoryIntent { .. }
                    | Event::RetirementContainerIntent { .. }
                    | Event::Created(_)
                    | Event::RecoveryRequired
            )
        }) {
            return Err(invalid());
        }
        if !self.raw_existing && self.prior.is_none() {
            self.append(Event::Skipped)?;
            return self.advance_state();
        }
        let anchor = self.target_anchor()?;
        // Existing destination needs no retirement namespace or filesystem mutations.
        let retirement = if self.raw_existing {
            anchor.directory.try_clone()?
        } else {
            self.retirement_container()?
        };
        match publish::publish_prior_state_if_absent(
            self,
            self,
            anchor,
            &retirement,
            self.uid,
            self.gid,
        ) {
            Ok(PublishOutcome::ExistingUnchanged) => self.advance_state(),
            Ok(PublishOutcome::Created(receipt)) => {
                self.phase(Phase::State)?;
                let admitted = self.newest_created()?;
                if serde_json::to_vec(&admitted).map_err(|_| invalid())?
                    != serde_json::to_vec(&receipt).map_err(|_| invalid())?
                {
                    return Err(invalid());
                }
                Ok(())
            }
            Err(_) => Err(invalid()),
        }
    }
    /// No broad cleanup. Existing/unowned/skipped state is preserved. Service-
    /// writable parents explicitly refuse retirement and retain stage/state.
    pub(super) fn rollback_state(&self) -> io::Result<StateRollback> {
        self.verify()?;
        let logs = self.logs()?;
        let phase = {
            let g = self.stage.try_borrow().map_err(|_| invalid())?;
            self.protected(&g)?;
            if g.header.capture_started {
                return Err(invalid());
            }
            g.header.phase
        };
        if !matches!(
            phase,
            Phase::Custody | Phase::State | Phase::Config | Phase::Metadata | Phase::Finalized
        ) {
            return Err(invalid());
        }
        // RecoveryRequired is terminal for this transaction, including on a second CLI entry.
        if logs
            .iter()
            .any(|r| matches!(r.event, Event::RecoveryRequired))
        {
            return Err(invalid());
        }
        if logs.last().is_some_and(|r| {
            matches!(
                r.event,
                Event::PublishIntent(_)
                    | Event::DirectoryIntent { .. }
                    | Event::RetirementContainerIntent { .. }
                    | Event::RetirementIntent { .. }
            )
        }) {
            return Err(invalid());
        }
        if logs
            .iter()
            .any(|r| matches!(r.event, Event::Retired { .. }))
        {
            return Ok(StateRollback::NoActionProven);
        }
        let Some(receipt) = logs.iter().rev().find_map(|r| match &r.event {
            Event::Created(c) => Some(c.clone()),
            _ => None,
        }) else {
            let no_action = match logs.last().map(|r| &r.event) {
                None => phase == Phase::Custody,
                Some(Event::Skipped) => !self.raw_existing && self.prior.is_none(),
                Some(Event::ExistingUnowned { .. }) => self.raw_existing,
                Some(
                    Event::PublishNotLinked
                    | Event::DirectoryCreated { .. }
                    | Event::RetirementContainerCreated { .. },
                ) => phase == Phase::Custody,
                _ => false,
            };
            return if no_action {
                Ok(StateRollback::NoActionProven)
            } else {
                Err(invalid())
            };
        };
        self.admit_rollback(&receipt)?;
        let parent = self.target_anchor()?;
        if !parent.missing_suffix.is_empty() {
            return Err(invalid());
        }
        let retirement = self.retirement_container()?;
        publish::retire_owned_created_state(
            self,
            &parent.directory,
            &retirement,
            &format!("state-retired-{}", self.nonce),
            &receipt,
        )
        .map_err(|_| invalid())?;
        Ok(StateRollback::RetiredOwned)
    }
    /// Reads only the exact newly-owned published inode. ExistingUnchanged cannot
    /// mint an own receipt and has no original-path byte-read fallback.
    fn read_owned_published_state(
        stage: &StageGuard,
        relative: &Path,
    ) -> io::Result<Zeroizing<Vec<u8>>> {
        // The stateless Store adapter supplies the same admitted StageGuard;
        // the shared reader validates its sealed generation and own receipt.
        read_stage_owned_state(stage, relative)
    }
    /// Interrupted file intent is authenticated by Header.state_records. Exact new
    /// inode + staged hash may prove own publication; foreign/malformed namespace
    /// is retained and refused, never promoted by shape/UID alone.
    pub(super) fn recover_pending(&self) -> io::Result<StateRecovery> {
        self.verify()?;
        let logs = self.logs()?;
        let phase = {
            let g = self.stage.try_borrow().map_err(|_| invalid())?;
            self.protected(&g)?;
            if g.header.capture_started {
                return Err(invalid());
            }
            g.header.phase
        };
        if !matches!(
            phase,
            Phase::Custody | Phase::State | Phase::Config | Phase::Metadata | Phase::Finalized
        ) {
            return Err(invalid());
        }
        if logs
            .iter()
            .any(|r| matches!(r.event, Event::RecoveryRequired))
        {
            return Err(invalid());
        }
        let Some(last) = logs.last() else {
            return Ok(StateRecovery::NoPending);
        };
        if let Event::PublishIntent(intent) = &last.event {
            if phase != Phase::Custody {
                return Err(invalid());
            }
            let anchor = self.target_anchor()?;
            if !anchor.missing_suffix.is_empty() {
                return Err(invalid());
            }
            match self.named_state(&anchor.directory) {
                Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                    self.append(Event::PublishNotLinked)?;
                    Ok(StateRecovery::Resolved)
                }
                Ok((_, n)) => {
                    let current = StateReceipt {
                        parent: node(&anchor.directory)?,
                        file: n,
                        private_sha256: intent.private_sha256,
                    };
                    if !linked(intent, &current) {
                        self.append(Event::RecoveryRequired)?;
                        return Err(invalid());
                    }
                    let (pinned, verified) = self.named_state(&anchor.directory)?;
                    if verified != current.file {
                        return Err(invalid());
                    }
                    let _owned = read_owned_fd(&anchor.directory, &pinned, &current)?;
                    if self.named_state(&anchor.directory)?.1 != current.file {
                        return Err(invalid());
                    }
                    self.append(Event::Created(current))?;
                    self.advance_state()?;
                    Ok(StateRecovery::Resolved)
                }
                Err(_) => {
                    self.append(Event::RecoveryRequired)?;
                    Err(invalid())
                }
            }
        } else if matches!(
            last.event,
            Event::DirectoryIntent { .. }
                | Event::RetirementContainerIntent { .. }
                | Event::RetirementIntent { .. }
        ) {
            if phase == Phase::Custody {
                self.append(Event::RecoveryRequired)?;
            }
            Err(invalid())
        } else if matches!(last.event, Event::Created(_)) && phase == Phase::Custody {
            // Created was persisted but phase advancement may have been interrupted.
            {
                let g = self.stage.try_borrow().map_err(|_| invalid())?;
                let _owned = read_stage_owned_state(&g, Path::new("state.json"))?;
            }
            self.advance_state()?;
            Ok(StateRecovery::Resolved)
        } else {
            Ok(StateRecovery::NoPending)
        }
    }
}
/// Stateless reader borrows the SAME admitted held StageGuard supplied by the
/// actual RootContext. Existing/unowned runtime state has no own-receipt fallback.
pub(super) struct PublishedState;
impl super::store_context::StateContext for PublishedState {
    fn read_owned_published_state(
        &self,
        stage: &StageGuard,
        relative: &Path,
    ) -> std::result::Result<Zeroizing<Vec<u8>>, &'static str> {
        StateContext::read_owned_published_state(stage, relative)
            .map_err(|_| "Protected AUTO own state read refused")
    }
}
fn read_stage_owned_state(stage: &StageGuard, relative: &Path) -> io::Result<Zeroizing<Vec<u8>>> {
    if relative != Path::new("state.json") {
        return Err(invalid());
    }
    SealedStageAuthority::revalidate(stage)?;
    let uid = stage.header.service_uid.ok_or_else(invalid)?;
    let gid = stage.header.service_gid.ok_or_else(invalid)?;
    let mut predecessor = None;
    let mut created = None;
    let mut retired = false;
    let mut pending_file: Option<StateReceipt> = None;
    for (ordinal, (leaf, sha)) in stage.header.state_records.iter().enumerate() {
        if leaf.as_path() != Path::new(&format!("receipts/state/{ordinal:04}.json")) {
            return Err(invalid());
        }
        let bytes = convert(stage.store.read(leaf))?;
        if digest(&bytes) != *sha {
            return Err(invalid());
        }
        let r: Envelope = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if r.schema != 1
            || r.nonce != stage.header.transaction_nonce
            || r.input != stage.header.input_generation
            || r.planned != stage.header.planned_generation
            || r.mode != stage.header.mode.name()
            || r.uid != uid
            || r.gid != gid
            || r.target != stage.header.state_dir
            || r.ordinal != ordinal
            || r.predecessor != predecessor
        {
            return Err(invalid());
        }
        match r.event {
            Event::PublishIntent(i) => pending_file = Some(i),
            Event::PublishNotLinked => pending_file = None,
            Event::Created(c) => {
                if pending_file.as_ref().is_none_or(|i| !linked(i, &c)) {
                    return Err(invalid());
                }
                pending_file = None;
                created = Some(c);
                retired = false;
            }
            Event::Retired { .. } | Event::RecoveryRequired => retired = true,
            _ => {}
        }
        predecessor = Some(sha.clone());
    }
    if retired {
        return Err(invalid());
    }
    let receipt = created.ok_or_else(invalid)?;
    if stage.header.leaves.get(Path::new(ACCEPTED)) != Some(&hex::encode(receipt.private_sha256)) {
        return Err(invalid());
    }
    let parent = open_absolute_state_dir(&stage.header.state_dir, uid, gid)?;
    let pinned = raw_open(&parent, "state.json", libc::O_PATH | libc::O_NONBLOCK)?;
    if !static_dir(&node(&parent)?, &receipt.parent) || node(&pinned)? != receipt.file {
        return Err(invalid());
    }
    let bytes = read_owned_fd(&parent, &pinned, &receipt)?;
    let current = raw_open(&parent, "state.json", libc::O_PATH | libc::O_NONBLOCK)?;
    if node(&current)? != receipt.file {
        return Err(invalid());
    }
    SealedStageAuthority::revalidate(stage)?;
    Ok(bytes)
}

impl VerifiedStateBytes for StateContext<'_> {
    fn revalidate(&self) -> io::Result<()> {
        self.verify()
    }
    fn bytes(&self) -> io::Result<&[u8]> {
        if self.raw_existing {
            return Ok(&[]);
        }
        self.prior
            .as_deref()
            .map(|v| v.as_slice())
            .ok_or_else(invalid)
    }
}
impl StateAuthority for StateContext<'_> {
    fn revalidate(&self) -> io::Result<()> {
        self.verify()
    }
    fn admit_destination(
        &self,
        anchor: &DestinationAnchor,
        stage: &dyn VerifiedStateBytes,
        uid: u32,
        gid: u32,
    ) -> io::Result<DestinationDisposition> {
        self.phase(Phase::Custody)?;
        if uid != self.uid || gid != self.gid {
            return Err(invalid());
        }
        let actual = self.target_anchor()?;
        if !static_dir(&anchor.expected_directory, &actual.expected_directory)
            || anchor.missing_suffix != actual.missing_suffix
        {
            return Err(invalid());
        }
        let prior_steps = self
            .logs()?
            .iter()
            .filter(|r| matches!(r.event, Event::DirectoryCreated { .. }))
            .count();
        self.anchor.replace(Some((
            anchor.expected_directory.clone(),
            anchor.missing_suffix.clone(),
            prior_steps,
        )));
        if anchor.missing_suffix.is_empty()
            && !state_writer_ready(&anchor.expected_directory, self.uid, self.gid)
        {
            return Err(invalid());
        }
        if self.raw_existing {
            if !anchor.missing_suffix.is_empty() {
                return Err(invalid());
            }
            return Ok(DestinationDisposition::ExistingUnchanged);
        }
        self.validate_prior_generation()?;
        let bytes = stage.bytes()?;
        if self.prior_hash.as_ref() != Some(&digest(bytes))
            || self.prior.as_deref().is_none_or(|p| p.as_slice() != bytes)
        {
            return Err(invalid());
        }
        let owned_dirs = self
            .logs()?
            .iter()
            .any(|r| matches!(r.event, Event::DirectoryCreated { .. }));
        if !owned_dirs {
            let guard = capture::reopen_generation(&self.original)?;
            guard.revalidate()?;
            self.initial.replace(Some(guard));
        }
        Ok(DestinationDisposition::Absent)
    }
    fn verify_existing_destination(&self, parent: &File) -> io::Result<()> {
        self.phase(Phase::Custody)?;
        if !self.raw_existing {
            return Err(invalid());
        }
        let (_, file) = self.named_state(parent)?;
        if self.uid != 0 && file.uid != self.uid {
            return Err(invalid());
        }
        if !state_writer_ready(&node(parent)?, self.uid, self.gid) {
            return Err(invalid());
        }
        let actual = self.target_anchor()?;
        let p = node(parent)?;
        if !actual.missing_suffix.is_empty() || !static_dir(&p, &actual.expected_directory) {
            return Err(invalid());
        }
        self.append(Event::ExistingUnowned { parent: p, file })
    }
    fn record_directory_intent(
        &self,
        parent: &NodeIdentity,
        name: &str,
        uid: u32,
        gid: u32,
        mode: u32,
    ) -> io::Result<()> {
        self.phase(Phase::Custody)?;
        let anchor = self.anchor.borrow();
        let (base, suffix, offset) = anchor.as_ref().ok_or_else(invalid)?;
        let logs = self.logs()?;
        let steps: Vec<_> = logs
            .iter()
            .filter_map(|r| match &r.event {
                Event::DirectoryCreated { node, .. } => Some(node),
                _ => None,
            })
            .collect();
        let new_steps = &steps[(*offset).min(steps.len())..];
        let index = new_steps.len();
        if suffix.get(index).is_none_or(|n| n != name)
            || !static_dir(parent, new_steps.last().copied().unwrap_or(base))
        {
            return Err(invalid());
        }
        let expected = if index + 1 == suffix.len() {
            (self.uid, self.gid, 0o700)
        } else {
            (0, 0, 0o755)
        };
        if (uid, gid, mode) != expected {
            return Err(invalid());
        }
        if index == 0 {
            if let Some(g) = self.initial.borrow().as_ref() {
                g.revalidate()?;
            }
        }
        self.append(Event::DirectoryIntent {
            parent: parent.clone(),
            name: name.into(),
            uid,
            gid,
            mode,
        })
    }
    fn record_directory_created(
        &self,
        parent: &NodeIdentity,
        name: &str,
        n: &NodeIdentity,
    ) -> io::Result<()> {
        self.phase(Phase::Custody)?;
        let logs = self.logs()?;
        let last = logs.last().ok_or_else(invalid)?;
        let Event::DirectoryIntent {
            parent: p,
            name: expected,
            uid,
            gid,
            mode,
        } = &last.event
        else {
            return Err(invalid());
        };
        if !static_dir(p, parent)
            || expected != name
            || n.dev != parent.dev
            || n.uid != *uid
            || n.gid != *gid
            || n.mode & 0o777 != *mode
            || n.mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(invalid());
        }
        self.append(Event::DirectoryCreated {
            parent: parent.clone(),
            name: name.into(),
            node: n.clone(),
        })?;
        self.initial.replace(None);
        Ok(())
    }
    fn record_publish_intent(&self, intent: &StateReceipt) -> io::Result<()> {
        self.phase(Phase::Custody)?;
        self.validate_prior_generation()?;
        let expected = self.prior.as_ref().ok_or_else(invalid)?;
        use sha2::Digest;
        let hash: [u8; 32] = sha2::Sha256::digest(expected.as_slice()).into();
        let target = self.target_anchor()?;
        if !target.missing_suffix.is_empty()
            || !static_dir(&intent.parent, &target.expected_directory)
            || intent.file.uid != self.uid
            || intent.file.gid != self.gid
            || intent.file.mode & 0o777 != 0o600
            || intent.file.links != 0
            || intent.file.len != expected.len() as u64
            || intent.private_sha256 != hash
        {
            return Err(invalid());
        }
        if let Some(g) = self.initial.borrow().as_ref() {
            g.revalidate()?;
        }
        self.append(Event::PublishIntent(intent.clone()))
    }
    fn record_created(&self, receipt: &StateReceipt) -> io::Result<()> {
        self.phase(Phase::Custody)?;
        let logs = self.logs()?;
        let Event::PublishIntent(intent) = &logs.last().ok_or_else(invalid)?.event else {
            return Err(invalid());
        };
        if !linked(intent, receipt) {
            return Err(invalid());
        }
        self.append(Event::Created(receipt.clone()))?;
        self.initial.replace(None);
        self.advance_state()
    }
    fn admit_rollback(&self, receipt: &StateReceipt) -> io::Result<()> {
        self.verify()?;
        let g = self.stage.try_borrow().map_err(|_| invalid())?;
        if g.header.capture_started
            || !matches!(
                g.header.phase,
                Phase::State | Phase::Config | Phase::Metadata | Phase::Finalized
            )
        {
            return Err(invalid());
        }
        let owned = self.newest_created()?;
        if serde_json::to_vec(&owned).map_err(|_| invalid())?
            != serde_json::to_vec(receipt).map_err(|_| invalid())?
        {
            return Err(invalid());
        }
        Ok(())
    }
    fn record_retirement_intent(&self, receipt: &StateReceipt, name: &str) -> io::Result<()> {
        self.admit_rollback(receipt)?;
        if name != format!("state-retired-{}", self.nonce) {
            return Err(invalid());
        }
        self.append(Event::RetirementIntent {
            receipt: receipt.clone(),
            name: name.into(),
        })
    }
    fn record_retired(
        &self,
        receipt: &StateReceipt,
        name: &str,
        n: &NodeIdentity,
    ) -> io::Result<()> {
        self.admit_rollback(receipt)?;
        let logs = self.logs()?;
        let Event::RetirementIntent {
            receipt: r,
            name: expected,
        } = &logs.last().ok_or_else(invalid)?.event
        else {
            return Err(invalid());
        };
        if expected != name
            || r.file.dev != receipt.file.dev
            || r.file.ino != receipt.file.ino
            || n.dev != receipt.file.dev
            || n.ino != receipt.file.ino
        {
            return Err(invalid());
        }
        self.append(Event::Retired {
            receipt: receipt.clone(),
            name: name.into(),
            node: n.clone(),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn n(ino: u64) -> NodeIdentity {
        NodeIdentity {
            dev: 1,
            ino,
            mode: libc::S_IFDIR | 0o700,
            uid: 0,
            gid: 0,
            links: 2,
            len: 0,
            modified: (0, 0),
            changed: (0, 0),
        }
    }
    #[test]
    fn parent_binding_does_not_ignore_owner_mode_or_inode() {
        let a = n(1);
        let mut b = a.clone();
        assert!(static_dir(&a, &b));
        b.ino = 2;
        assert!(!static_dir(&a, &b));
        b = a.clone();
        b.uid = 9;
        assert!(!static_dir(&a, &b));
        b = a.clone();
        b.mode = libc::S_IFDIR | 0o777;
        assert!(!static_dir(&a, &b));
    }
    #[test]
    fn link_receipt_cannot_promote_other_inode_owner_or_size() {
        let mut file = n(7);
        file.mode = libc::S_IFREG | 0o600;
        file.links = 0;
        file.len = 4;
        let intent = StateReceipt {
            parent: n(1),
            file: file.clone(),
            private_sha256: [1; 32],
        };
        file.links = 1;
        let mut receipt = StateReceipt {
            parent: n(1),
            file,
            private_sha256: [1; 32],
        };
        assert!(linked(&intent, &receipt));
        receipt.file.ino = 8;
        assert!(!linked(&intent, &receipt));
        receipt.file.ino = 7;
        receipt.file.uid = 5;
        assert!(!linked(&intent, &receipt));
        receipt.file.uid = 0;
        receipt.file.len = 5;
        assert!(!linked(&intent, &receipt));
    }
    #[test]
    fn traversal_checks_real_uid_gid_permission_class() {
        let mut a = n(1);
        a.uid = 100;
        a.gid = 200;
        assert!(traversable(&a, 100, 300));
        assert!(!traversable(&a, 101, 300));
        a.mode = libc::S_IFDIR | 0o750;
        assert!(traversable(&a, 101, 200));
        assert!(!traversable(&a, 101, 201));
    }
    #[test]
    fn actual_owned_inode_fd_read_matches_private_receipt_and_refuses_mutation() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = d.path().join("state.json");
        fs::write(&path, b"synthetic owned state").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let parent = File::open(d.path()).unwrap();
        let pinned = raw_open(&parent, "state.json", libc::O_PATH | libc::O_NONBLOCK).unwrap();
        let receipt = StateReceipt {
            parent: node(&parent).unwrap(),
            file: node(&pinned).unwrap(),
            private_sha256: sha2::Sha256::digest(b"synthetic owned state").into(),
        };
        assert!(
            read_owned_fd(&parent, &pinned, &receipt)
                .unwrap()
                .as_slice()
                == b"synthetic owned state"
        );
        fs::write(&path, b"changed generation").unwrap();
        assert!(read_owned_fd(&parent, &pinned, &receipt).is_err());
    }
    #[test]
    fn actual_substituted_namespace_and_hardlink_never_read_as_owned_original() {
        use std::{fs, os::unix::fs::PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let path = d.path().join("state.json");
        fs::write(&path, b"owned").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let parent = File::open(d.path()).unwrap();
        let pinned = raw_open(&parent, "state.json", libc::O_PATH | libc::O_NONBLOCK).unwrap();
        let receipt = StateReceipt {
            parent: node(&parent).unwrap(),
            file: node(&pinned).unwrap(),
            private_sha256: sha2::Sha256::digest(b"owned").into(),
        };
        fs::rename(&path, d.path().join("retained-owned")).unwrap();
        fs::write(&path, b"foreign original").unwrap();
        assert!(read_owned_fd(&parent, &pinned, &receipt).is_err());
        assert!(fs::read(&path).unwrap() == b"foreign original");
        let fresh = raw_open(&parent, "state.json", libc::O_PATH | libc::O_NONBLOCK).unwrap();
        fs::hard_link(&path, d.path().join("extra-link")).unwrap();
        let forged = StateReceipt {
            parent: node(&parent).unwrap(),
            file: node(&fresh).unwrap(),
            private_sha256: sha2::Sha256::digest(b"foreign original").into(),
        };
        assert!(read_owned_fd(&parent, &fresh, &forged).is_err());
    }

    #[test]
    fn rapid_relocated_named_state_refuses_even_with_matching_inode_identity() {
        use std::{fs, os::unix::fs::PermissionsExt};
        for iteration in 0..64 {
            let d = tempfile::tempdir().unwrap();
            fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let path = d.path().join("state.json");
            fs::write(&path, b"owned").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let parent = File::open(d.path()).unwrap();
            let pinned = raw_open(&parent, "state.json", libc::O_PATH | libc::O_NONBLOCK).unwrap();
            let mut receipt = StateReceipt {
                parent: node(&parent).unwrap(),
                file: node(&pinned).unwrap(),
                private_sha256: sha2::Sha256::digest(b"owned").into(),
            };
            fs::rename(&path, d.path().join("retained-owned")).unwrap();
            fs::write(&path, b"foreign original").unwrap();
            // Model the fast-rename case deterministically: all pinned inode
            // metadata, including ctime, still agrees with the receipt.
            receipt.file = node(&pinned).unwrap();
            assert!(
                read_owned_fd(&parent, &pinned, &receipt).is_err(),
                "relocated named state accepted at iteration {iteration}"
            );
        }
    }

    fn actual_stage(
        mode: super::super::AutoMode,
        different_accepted: bool,
    ) -> (tempfile::TempDir, RefCell<StageGuard>) {
        use super::super::{
            authority::{Manifest, SourceBinding},
            durable::Store,
            Header, PROTOCOL,
        };
        use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt};
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let config = d.path().join("config");
        let state = d.path().join("state");
        let metadata = d.path().join("metadata");
        for p in [&config, &metadata] {
            fs::create_dir(p).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let prior = d.path().join("prior.json");
        fs::write(&prior, b"synthetic prior state").unwrap();
        fs::set_permissions(&prior, fs::Permissions::from_mode(0o600)).unwrap();
        let store = Store::create(d.path(), 0).unwrap();
        let mut leaves = BTreeMap::new();
        let mut sources = Vec::new();
        for (role, path, tree, input_role) in [
            (
                "config",
                &config,
                true,
                InputRole::ServiceInput {
                    service_uid: 0,
                    administrator_uid: 0,
                },
            ),
            (
                "state",
                &state,
                true,
                InputRole::ServiceInput {
                    service_uid: 0,
                    administrator_uid: 0,
                },
            ),
            (
                "metadata",
                &metadata,
                true,
                InputRole::AdministratorMetadata {
                    administrator_uid: 0,
                },
            ),
            (
                "prior-state",
                &prior,
                false,
                InputRole::ServiceInput {
                    service_uid: 0,
                    administrator_uid: 0,
                },
            ),
        ] {
            let captured = capture::CapturedTree::capture_optional(
                path,
                path.parent().unwrap().into(),
                input_role,
                capture::CaptureLimits::default(),
                tree,
            )
            .unwrap();
            let generation =
                serde_json::to_vec(&captured.export_private_generation().unwrap()).unwrap();
            let leaf = PathBuf::from(format!("input/generations/{role}.json"));
            store.write_new(&leaf, &generation).unwrap();
            leaves.insert(leaf.clone(), digest(&generation));
            sources.push(SourceBinding {
                role: role.into(),
                original_path: path.clone(),
                generation_leaf: leaf,
                publication_witness_leaf: None,
            });
        }
        let manifest = Manifest {
            schema: 1,
            config_root: config.clone(),
            state_dir: state.clone(),
            metadata_dir: metadata.clone(),
            service_uid: 0,
            operator_uid: 0,
            logical_bundle: None,
            render_context: crate::profile_auto_render::RenderContext {
                mode: match mode {
                    super::super::AutoMode::SocksOnly => {
                        crate::profile_auto_render::SelectedMode::SocksOnly
                    }
                    super::super::AutoMode::WideRedirectSafe => {
                        crate::profile_auto_render::SelectedMode::WideRedirectSafe
                    }
                    super::super::AutoMode::FullWideTun => {
                        crate::profile_auto_render::SelectedMode::FullWideTun
                    }
                },
                logical_original_base: config.clone(),
                logical_final_base: config.clone(),
                final_state: state.join("state.json"),
                wide_interface: None,
            },
            sources,
            references: Vec::new(),
        };
        let authority = serde_json::to_vec(&manifest).unwrap();
        store
            .write_new(Path::new("input/authority.json"), &authority)
            .unwrap();
        leaves.insert(PathBuf::from("input/authority.json"), digest(&authority));
        for (leaf, bytes) in [
            (PRIOR, b"synthetic prior state".as_slice()),
            (
                ACCEPTED,
                if different_accepted {
                    b"unrelated accepted state".as_slice()
                } else {
                    b"synthetic prior state".as_slice()
                },
            ),
        ] {
            store.write_new(Path::new(leaf), bytes).unwrap();
            leaves.insert(PathBuf::from(leaf), digest(bytes));
        }
        let header_value = serde_json::json!({"protocol":PROTOCOL,"administrator_uid":0,"config_root":config,"state_dir":state,"metadata_dir":metadata,"phase":"custody","transaction_nonce":"00112233445566778899aabbccddeeff","current_records":{},"active_records":{},"pending":null,"mode":mode,"plan":{"schema":"aegis_auto_install_plan_v1","status":"planned","product_mode":mode.name(),"connectivity_verified":false},"service_uid":0,"service_gid":0,"state_records":{},"namespace_records":{},"runtime_events":"/dev/null","unit_records":{},"unit_role_records":{},"unit_forward_transitions":{},"unit_restorations":{},"render_recipe":"accepted/render-recipe.json","service_was_active":false,"capture_started":false,"leaves":leaves,"input_generation":"01".repeat(32),"accepted_generation":"02".repeat(32),"planned_generation":"02".repeat(32)});
        let header: Header = serde_json::from_value(header_value).unwrap();
        // Positive fixture must match the actual sixteen-byte producer contract.
        assert_eq!(header.transaction_nonce.len(), hex::encode([0u8; 16]).len());
        header.validate(0).unwrap();
        let bytes = serde_json::to_vec(&header).unwrap();
        store.write_new(Path::new("header.json"), &bytes).unwrap();
        let guard = StageGuard::admit(store).unwrap();
        (d, RefCell::new(guard))
    }
    #[test]
    #[ignore = "requires actual disposable Linux root protected Store fixture"]
    fn actual_legacy_stateless_reader_refuses_unowned_state_without_original_fallback() {
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let (_d, cell) = actual_stage(super::super::AutoMode::SocksOnly, false);
        let reader = PublishedState;
        assert!(
            super::super::store_context::StateContext::read_owned_published_state(
                &reader,
                &cell.borrow(),
                Path::new("state.json")
            )
            .is_err()
        );
    }
    #[test]
    fn actual_protected_stage_three_modes_cannot_fake_missing_custody_receipt() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for mode in [
            super::super::AutoMode::SocksOnly,
            super::super::AutoMode::WideRedirectSafe,
            super::super::AutoMode::FullWideTun,
        ] {
            let (d, cell) = actual_stage(mode, false);
            let context = StateContext::new(&cell).unwrap();
            assert!(VerifiedStateBytes::bytes(&context).unwrap() == b"synthetic prior state");
            assert!(context.commit_state().is_err());
            assert!(!d.path().join("state").exists());
            assert!(cell.borrow().header.state_records.is_empty());
        }
    }
    #[test]
    fn actual_sealed_prior_and_accepted_state_mismatch_refuses() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let (_d, cell) = actual_stage(super::super::AutoMode::SocksOnly, true);
        assert!(StateContext::new(&cell).is_err());
        assert!(cell.borrow().header.state_records.is_empty());
    }

    #[test]
    fn actual_state_writer_readiness_needs_directory_write_and_execute() {
        let mut directory = n(1);
        directory.uid = 100;
        directory.gid = 200;
        assert!(state_writer_ready(&directory, 100, 300));
        assert!(!state_writer_ready(&directory, 101, 300));
        directory.mode = libc::S_IFDIR | 0o750;
        assert!(traversable(&directory, 101, 200));
        assert!(!state_writer_ready(&directory, 101, 200));
        directory.mode = libc::S_IFDIR | 0o730;
        assert!(state_writer_ready(&directory, 101, 200));
    }

    #[test]
    fn actual_store_foreign_publish_intent_remains_unresolved_on_second_entry() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        use std::{fs, io::Write, os::unix::fs::PermissionsExt};
        let (d, cell) = actual_stage(super::super::AutoMode::SocksOnly, false);
        let target = d.path().join("state");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let context = StateContext::new(&cell).unwrap();
        let parent = File::open(&target).unwrap();
        let name = CString::new(".").unwrap();
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
                0o600,
            )
        };
        assert!(fd >= 0);
        let mut pending = unsafe { File::from_raw_fd(fd) };
        pending.write_all(b"synthetic prior state").unwrap();
        pending.sync_all().unwrap();
        context
            .append(Event::PublishIntent(StateReceipt {
                parent: node(&parent).unwrap(),
                file: node(&pending).unwrap(),
                private_sha256: sha2::Sha256::digest(b"synthetic prior state").into(),
            }))
            .unwrap();
        fs::write(target.join("state.json"), b"foreign synthetic state").unwrap();
        fs::set_permissions(target.join("state.json"), fs::Permissions::from_mode(0o600)).unwrap();
        assert!(context.recover_pending().is_err());
        let first_count = cell.borrow().header.state_records.len();
        assert!(matches!(
            context.logs().unwrap().last().unwrap().event,
            Event::RecoveryRequired
        ));
        drop(context);
        let retry = StateContext::new(&cell).unwrap();
        assert!(retry.recover_pending().is_err());
        assert!(retry.rollback_state().is_err());
        assert!(cell.borrow().header.phase == Phase::Custody);
        assert_eq!(cell.borrow().header.state_records.len(), first_count);
        assert!(fs::read(target.join("state.json")).unwrap() == b"foreign synthetic state");
    }
    #[test]
    fn actual_store_completed_phases_allow_owned_state_retirement_not_false_pending() {
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        for phase in [
            Phase::State,
            Phase::Config,
            Phase::Metadata,
            Phase::Finalized,
        ] {
            let (d, cell) = actual_stage(super::super::AutoMode::SocksOnly, false);
            let context = StateContext::new(&cell).unwrap();
            // Component-level actual StateAuthority/Store publication, not a claim that
            // this synthetic fixture contains a completed config custody transaction.
            let anchor = context.target_anchor().unwrap();
            let retirement = context.retirement_container().unwrap();
            assert!(matches!(
                publish::publish_prior_state_if_absent(
                    &context,
                    &context,
                    anchor,
                    &retirement,
                    0,
                    0
                )
                .unwrap(),
                PublishOutcome::Created(_)
            ));
            {
                let mut g = cell.borrow_mut();
                g.header.phase = phase;
                g.persist_header().unwrap();
            }
            assert!(context.recover_pending().unwrap() == StateRecovery::NoPending);
            assert!(context.rollback_state().unwrap() == StateRollback::RetiredOwned);
            assert!(!d.path().join("state/state.json").exists());
            assert!(matches!(
                context.logs().unwrap().last().unwrap().event,
                Event::Retired { .. }
            ));
            assert!(context.rollback_state().unwrap() == StateRollback::NoActionProven);
        }
    }
}
