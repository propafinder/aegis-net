//! B-06 S15: the host import client behind `aegis-ne-host --import DIR
//! [--remove-source]`.
//!
//! `SourceTree::open` admits one self-contained `Aegis` source directory
//! before anything is sent: a canonical absolute path (no symlink anywhere
//! in it), a real 0700 directory owned by the caller holding exactly
//! `bundle/` and `identity/`, each a real directory of the caller with no
//! group or other permission bits, holding only import members (and the
//! Store's empty `.lock`). Every file is opened through the held directory
//! descriptors with `O_NOFOLLOW`, must be a regular file of the caller with
//! one link and within its member cap, and is read into a zeroizing buffer;
//! identity files must also carry no group or other bits. A bridge sidecar
//! must name its credential at `DIR/identity/bridge-credential`, so every
//! byte that is sent lies inside the admitted tree.
//!
//! `conclude_import` decides what happens to the source after the one
//! bounded XPC exchange: only a decoded `import` reply whose committed
//! manifest matches every sent path, and every sent length and digest
//! except the provider-rewritten bridge sidecar's, whose presence alone is
//! checked (`verify_import_report`, checked again here because this decides
//! deletion), may remove the source, and only with `--remove-source`.
//! A refusal made before the provider's commit is `refused` (65); a
//! failure that cannot have reached the provider is `unavailable` (69);
//! anything after delivery that does not say whether the provider
//! committed (interrupted connection, malformed reply, a post-commit
//! refusal) is `unknown` (77), like the timeout (75).
//! Removal first re-checks the whole tree (same inodes, same entries, same
//! digests as sent) and removes nothing unless all of it is unchanged.
//! The result line names codes, counts and booleans only, never a path,
//! digest or file byte.
use crate::{
    host_lifecycle::{
        xpc_error_exit, EXIT_IMPORT_COMMIT_UNKNOWN, EXIT_IMPORT_MANIFEST_MISMATCH,
        EXIT_IMPORT_SOURCE_NOT_REMOVED, EXIT_XPC_REFUSED, EXIT_XPC_REMOVAL_INCOMPLETE,
    },
    identity_import::{
        fstat, id, list, open_dir_at, sha256_hex, stat_at, verify_import_report, Dir, Id,
        ImportManifest, ImportPayload, BRIDGE_CREDENTIAL, IMPORT_COMMIT_UNVERIFIED, IMPORT_MEMBERS,
        SFU_SIDECAR_MEMBER, SIDECAR_MEMBER, WEB_RESPONSE_CREDENTIAL, WEB_SIDECAR_MEMBER,
    },
    provider_xpc::Reply,
};
use aegis_core::https_bridge::ClientSettings as BridgeSettings;
use aegis_core::web_response_profile::WebResponseSettings;
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
    fs::File,
    io::Read,
    os::fd::{AsRawFd, FromRawFd},
    path::Path,
};
use zeroize::Zeroizing;

const LOCK: &CStr = c".lock";

/// One admitted source entry: where it is, which inode it was, and which
/// import member it was sent as (`None` for the Store's `.lock`).
struct SourceFile {
    dir: Dir,
    leaf: CString,
    id: Id,
    member: Option<usize>,
}

/// One admitted source directory and the payload read from it. Holds the
/// directory descriptors it was read through; nothing is resolved by path
/// again after `open`.
pub struct SourceTree {
    uid: u32,
    parent: File,
    name: CString,
    root: File,
    root_id: Id,
    bundle: File,
    bundle_id: Id,
    identity: File,
    identity_id: Id,
    files: Vec<SourceFile>,
    payload: ImportPayload,
}

/// What `--remove-source` did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceRemoval {
    /// The whole directory is gone.
    Removed,
    /// Nothing was removed: the tree is not exactly what was sent.
    Kept(&'static str),
    /// Some entries were removed, but the directory still exists.
    Incomplete,
}

fn private_mode(stat: &libc::stat, uid: u32, exact_0700: bool) -> Result<(), &'static str> {
    if stat.st_uid != uid {
        return Err("import_source_not_owned");
    }
    let mode = stat.st_mode & 0o7777;
    if (exact_0700 && mode != 0o700) || mode & 0o7077 != 0 {
        return Err("import_source_not_private");
    }
    Ok(())
}

/// A real private directory `name` below `parent`, never through a link.
fn open_source_dir(
    parent: &File,
    name: &CStr,
    uid: u32,
    exact_0700: bool,
) -> Result<(File, Id), &'static str> {
    let named = match stat_at(parent, name) {
        Ok(stat) => stat,
        Err(libc::ENOENT) => return Err("import_source_missing"),
        Err(_) => return Err("import_source_unreadable"),
    };
    match named.st_mode & libc::S_IFMT {
        libc::S_IFDIR => {}
        libc::S_IFLNK => return Err("import_source_symlink"),
        _ => return Err("import_source_not_directory"),
    }
    let dir = open_dir_at(parent, name).map_err(|errno| match errno {
        libc::ELOOP => "import_source_symlink",
        libc::ENOTDIR => "import_source_not_directory",
        _ => "import_source_unreadable",
    })?;
    let held = fstat(&dir).map_err(|_| "import_source_unreadable")?;
    if id(&held) != id(&named) {
        return Err("import_source_changed");
    }
    private_mode(&held, uid, exact_0700)?;
    Ok((dir, id(&held)))
}

fn open_leaf(dir: &File, leaf: &CStr) -> Result<File, i32> {
    let raw = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        Err(crate::identity_import::last_errno())
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}

/// The bytes of one source file and the inode they were read from.
type SourceBytes = (Zeroizing<Vec<u8>>, Id);

/// One source file: a regular file of `uid` with one link, at most `cap`
/// bytes, never through a link. `Ok(None)` when it is absent.
fn read_leaf(
    dir: &File,
    leaf: &CStr,
    cap: usize,
    uid: u32,
    private: bool,
) -> Result<Option<SourceBytes>, &'static str> {
    let file = match open_leaf(dir, leaf) {
        Ok(file) => file,
        Err(libc::ENOENT) => return Ok(None),
        Err(libc::ELOOP) => return Err("import_source_symlink"),
        Err(_) => return Err("import_source_unreadable"),
    };
    let stat = fstat(&file).map_err(|_| "import_source_unreadable")?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
        return Err("import_source_not_regular");
    }
    if stat.st_uid != uid {
        return Err("import_source_not_owned");
    }
    if stat.st_nlink != 1 {
        return Err("import_source_linked");
    }
    if private && stat.st_mode & 0o077 != 0 {
        return Err("import_source_not_private");
    }
    if stat.st_size < 0 || stat.st_size as u64 > cap as u64 {
        return Err("import_source_oversized");
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(cap + 1));
    (&file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "import_source_unreadable")?;
    if bytes.len() > cap {
        return Err("import_source_oversized");
    }
    Ok(Some((bytes, id(&stat))))
}

fn names(dir: &File) -> Result<BTreeSet<CString>, &'static str> {
    Ok(list(dir)
        .ok_or("import_source_unreadable")?
        .into_iter()
        .collect())
}

fn leaves(dir: Dir) -> BTreeSet<CString> {
    IMPORT_MEMBERS
        .iter()
        .filter(|m| m.dir == dir)
        .filter_map(|m| CString::new(m.leaf).ok())
        .collect()
}

impl SourceTree {
    /// Admit `dir` for the calling user (euid).
    pub fn open(dir: &Path) -> Result<Self, &'static str> {
        Self::open_for(dir, unsafe { libc::geteuid() })
    }

    /// Admit `dir` for `uid`, which must own every entry.
    pub(crate) fn open_for(dir: &Path, uid: u32) -> Result<Self, &'static str> {
        if !dir.is_absolute() {
            return Err("import_dir_must_be_absolute");
        }
        // One spelling: no symlink component, `.`, `..` or doubled slash.
        match std::fs::canonicalize(dir) {
            Ok(canonical) if canonical.as_os_str() == dir.as_os_str() => {}
            Ok(_) => return Err("import_source_not_canonical"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err("import_source_missing")
            }
            Err(_) => return Err("import_source_unreadable"),
        }
        let (Some(parent_path), Some(leaf)) = (dir.parent(), dir.file_name()) else {
            return Err("import_source_not_directory");
        };
        let parent_name = CString::new(parent_path.as_os_str().as_encoded_bytes())
            .map_err(|_| "import_source_unreadable")?;
        let raw = unsafe {
            libc::open(
                parent_name.as_ptr(),
                crate::identity_import::DIRECTORY_FLAGS,
            )
        };
        if raw < 0 {
            return Err("import_source_unreadable");
        }
        let parent = unsafe { File::from_raw_fd(raw) };
        let name = CString::new(leaf.as_encoded_bytes()).map_err(|_| "import_source_unreadable")?;
        let (root, root_id) = open_source_dir(&parent, &name, uid, true)?;

        let expected_root = BTreeSet::from([c"bundle".to_owned(), c"identity".to_owned()]);
        let at_root = names(&root)?;
        if !at_root.is_subset(&expected_root) {
            return Err("import_source_unexpected_entry");
        }
        let (bundle, bundle_id) = open_source_dir(&root, Dir::Bundle.name(), uid, false)?;
        let (identity, identity_id) = open_source_dir(&root, Dir::Identity.name(), uid, false)?;
        if !names(&bundle)?.is_subset(&leaves(Dir::Bundle)) {
            return Err("import_source_unexpected_entry");
        }
        let identity_names = names(&identity)?;
        let mut allowed = leaves(Dir::Identity);
        allowed.insert(LOCK.to_owned());
        if !identity_names.is_subset(&allowed) {
            return Err("import_source_unexpected_entry");
        }

        let mut files = Vec::new();
        let mut members = Vec::new();
        for (index, m) in IMPORT_MEMBERS.iter().enumerate() {
            let held = match m.dir {
                Dir::Bundle => &bundle,
                Dir::Identity => &identity,
            };
            let leaf = CString::new(m.leaf).map_err(|_| "import_source_unreadable")?;
            let read = read_leaf(held, &leaf, m.cap, uid, m.dir == Dir::Identity)?;
            let Some((bytes, file_id)) = read else {
                if m.required() {
                    return Err("import_source_missing");
                }
                continue;
            };
            if index == SIDECAR_MEMBER {
                let settings: BridgeSettings = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|text| toml::from_str(text).ok())
                    .ok_or("import_source_sidecar_invalid")?;
                // The credential is read from inside the admitted tree only.
                if settings.credential_file != dir.join("identity").join(BRIDGE_CREDENTIAL) {
                    return Err("import_source_credential_outside");
                }
            }
            if index == WEB_SIDECAR_MEMBER {
                let settings: WebResponseSettings = std::str::from_utf8(&bytes)
                    .ok()
                    .and_then(|text| toml::from_str(text).ok())
                    .ok_or("import_source_sidecar_invalid")?;
                settings
                    .validate()
                    .map_err(|_| "import_source_sidecar_invalid")?;
                if settings.credential_file != dir.join("identity").join(WEB_RESPONSE_CREDENTIAL) {
                    return Err("import_source_credential_outside");
                }
            }
            if index == SFU_SIDECAR_MEMBER {
                crate::sfu_media_custody::admit_sidecar(&bytes, &dir.join("identity"))
                    .map_err(|_| "import_source_sidecar_invalid")?;
            }
            files.push(SourceFile {
                dir: m.dir,
                leaf,
                id: file_id,
                member: Some(index),
            });
            members.push((m.name(), bytes));
        }
        if identity_names.contains(LOCK) {
            // The Store's lock: an empty private regular file, never sent.
            match read_leaf(&identity, LOCK, 0, uid, true) {
                Ok(Some((_, lock_id))) => files.push(SourceFile {
                    dir: Dir::Identity,
                    leaf: LOCK.to_owned(),
                    id: lock_id,
                    member: None,
                }),
                Ok(None) => return Err("import_source_changed"),
                Err("import_source_oversized") => return Err("import_source_lock_invalid"),
                Err(code) => return Err(code),
            }
        }
        // The same manifest checks the provider applies (count, caps,
        // required files, bridge pair).
        let payload = ImportPayload::from_members(members)?;
        Ok(Self {
            uid,
            parent,
            name,
            root,
            root_id,
            bundle,
            bundle_id,
            identity,
            identity_id,
            files,
            payload,
        })
    }

    pub fn payload(&self) -> &ImportPayload {
        &self.payload
    }

    #[cfg(test)]
    pub(crate) fn into_payload(self) -> ImportPayload {
        self.payload
    }

    fn dir(&self, dir: Dir) -> &File {
        match dir {
            Dir::Bundle => &self.bundle,
            Dir::Identity => &self.identity,
        }
    }

    /// The tree is still exactly what was read and sent: the same three
    /// directories at their names, the same entries in each, every file the
    /// same single-link inode with the sent length and digest.
    fn unchanged(&self, sent: &ImportManifest) -> Result<(), &'static str> {
        let changed = "import_source_changed";
        let at = |parent: &File, name: &CStr, expected: Id| -> Result<(), &'static str> {
            match stat_at(parent, name) {
                Ok(stat) if id(&stat) == expected => Ok(()),
                _ => Err(changed),
            }
        };
        at(&self.parent, &self.name, self.root_id)?;
        at(&self.root, Dir::Bundle.name(), self.bundle_id)?;
        at(&self.root, Dir::Identity.name(), self.identity_id)?;
        if names(&self.root).map_err(|_| changed)?
            != BTreeSet::from([c"bundle".to_owned(), c"identity".to_owned()])
        {
            return Err(changed);
        }
        for dir in [Dir::Bundle, Dir::Identity] {
            let expected: BTreeSet<CString> = self
                .files
                .iter()
                .filter(|f| f.dir == dir)
                .map(|f| f.leaf.clone())
                .collect();
            if names(self.dir(dir)).map_err(|_| changed)? != expected {
                return Err(changed);
            }
        }
        for file in &self.files {
            let entry = match file.member {
                Some(member) => Some(
                    sent.entries()
                        .iter()
                        .find(|entry| entry.member == member)
                        .ok_or(changed)?,
                ),
                None => None,
            };
            let cap = file.member.map_or(0, |member| IMPORT_MEMBERS[member].cap);
            let read = read_leaf(self.dir(file.dir), &file.leaf, cap, self.uid, false)
                .map_err(|_| changed)?
                .ok_or(changed)?;
            if read.1 != file.id {
                return Err(changed);
            }
            if let Some(entry) = entry {
                if read.0.len() != entry.length || sha256_hex(&read.0) != entry.sha256 {
                    return Err(changed);
                }
            }
        }
        Ok(())
    }

    /// Remove the whole source after an exact commit. Nothing is removed
    /// unless the tree is unchanged since it was read and sent; then each
    /// file and directory is unlinked through its held parent descriptor.
    /// Unlinking is the guarantee; APFS copy-on-write, snapshots and backups
    /// are outside it.
    pub fn remove(&self, sent: &ImportManifest) -> SourceRemoval {
        if let Err(code) = self.unchanged(sent) {
            return SourceRemoval::Kept(code);
        }
        for file in &self.files {
            unsafe { libc::unlinkat(self.dir(file.dir).as_raw_fd(), file.leaf.as_ptr(), 0) };
        }
        for dir in [Dir::Bundle, Dir::Identity] {
            unsafe {
                libc::unlinkat(
                    self.root.as_raw_fd(),
                    dir.name().as_ptr(),
                    libc::AT_REMOVEDIR,
                )
            };
        }
        unsafe {
            libc::unlinkat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        };
        let _ = self.parent.sync_all();
        match stat_at(&self.parent, &self.name) {
            Err(libc::ENOENT) => SourceRemoval::Removed,
            _ => SourceRemoval::Incomplete,
        }
    }
}

/// The host's one result for `--import`: a stdout line, an optional stderr
/// code line and the exit code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImportOutcome {
    pub stdout: String,
    pub stderr: Option<String>,
    pub exit: i32,
}

/// The stdout line when `--import` could not admit its source: nothing was
/// sent and the source is untouched.
pub const SOURCE_REFUSED_LINE: &str = "import_result=not_sent manifest_match=false source=kept";
/// The stdout line when the commit state is unknown: no reply arrived in
/// time (exit 75), or the request may have reached the provider but no
/// decoded answer says whether it committed (exit 77). The source is kept.
pub const TIMEOUT_LINE: &str = "import_result=unknown manifest_match=unknown source=kept";
const COMMIT_UNKNOWN_LINE: &str = TIMEOUT_LINE;

/// Host-side failures after which the request cannot have reached the
/// provider: the connection or message was never created, the provider
/// requirement was not pinned or the peer failed it, or the service name
/// could not be looked up (`XPC_ERROR_CONNECTION_INVALID`; a provider that
/// exits after receipt is `XPC_ERROR_CONNECTION_INTERRUPTED` instead). Any
/// other failure (interrupted, a generic libxpc error, no reply, a reply
/// that does not decode) may follow a commit.
const NOT_DELIVERED: &[&str] = &[
    "xpc_connection_create_failed",
    "xpc_message_create_failed",
    "peer_requirement_not_set",
    "peer_requirement_unsatisfied",
    "service_unavailable",
];

/// Provider refusals it can only send after `renameatx_np` committed: the
/// read-back failed, or the committed report could not be encoded within
/// the reply bound (`provider_xpc::bounded`). Every other refusal is made
/// before the commit.
const AFTER_COMMIT_REFUSALS: &[&str] = &[
    IMPORT_COMMIT_UNVERIFIED,
    "reply_oversized",
    "reply_unencodable",
];

fn kept(result: &str, exit: i32, stderr: String) -> ImportOutcome {
    ImportOutcome {
        stdout: format!("import_result={result} manifest_match=false source=kept"),
        stderr: Some(stderr),
        exit,
    }
}

fn commit_unknown(stderr: String) -> ImportOutcome {
    ImportOutcome {
        stdout: COMMIT_UNKNOWN_LINE.into(),
        stderr: Some(stderr),
        exit: EXIT_IMPORT_COMMIT_UNKNOWN,
    }
}

/// Decide the result of one import exchange and, only for an exact commit
/// and with `remove_source`, remove the source.
pub fn conclude_import(
    source: &SourceTree,
    reply: Result<Reply, &'static str>,
    remove_source: bool,
) -> ImportOutcome {
    let sent = source.payload().manifest();
    let report = match reply {
        Ok(Reply::Import(report)) => report,
        Ok(Reply::Refused(code)) if AFTER_COMMIT_REFUSALS.contains(&code.as_str()) => {
            return commit_unknown(format!("provider_refused {code}"))
        }
        Ok(Reply::Refused(code)) => {
            return kept(
                "refused",
                EXIT_XPC_REFUSED,
                format!("provider_refused {code}"),
            )
        }
        // A decoded answer to another verb: delivered, state unknown.
        Ok(_) => return commit_unknown("reply_verb_mismatch".into()),
        // The provider's report decoded but names a different commit.
        Err(code) if xpc_error_exit(code) == EXIT_IMPORT_MANIFEST_MISMATCH => {
            return kept(
                "manifest_mismatch",
                EXIT_IMPORT_MANIFEST_MISMATCH,
                code.into(),
            )
        }
        Err(code) if NOT_DELIVERED.contains(&code) => {
            return kept("unavailable", xpc_error_exit(code), code.into())
        }
        Err(code) => return commit_unknown(code.into()),
    };
    // `query_import` already compared the echo; this decides deletion, so
    // it is compared again here.
    if let Err(code) = verify_import_report(&sent, &report) {
        return kept(
            "manifest_mismatch",
            EXIT_IMPORT_MANIFEST_MISMATCH,
            code.into(),
        );
    }
    let (source_state, source_failure) = if !remove_source {
        ("kept", None)
    } else {
        match source.remove(&sent) {
            SourceRemoval::Removed => ("removed", None),
            SourceRemoval::Kept(code) => ("kept", Some(code)),
            SourceRemoval::Incomplete => (
                "removal_incomplete",
                Some("import_source_removal_incomplete"),
            ),
        }
    };
    let exit = if !report.retired_removed {
        EXIT_XPC_REMOVAL_INCOMPLETE
    } else if source_failure.is_some() {
        EXIT_IMPORT_SOURCE_NOT_REMOVED
    } else {
        0
    };
    ImportOutcome {
        stdout: format!(
            "import_result=committed manifest_match=true committed_files={} retired_removed={} remove_source={remove_source} source={source_state}",
            report.files.len(),
            report.retired_removed,
        ),
        stderr: source_failure.map(String::from),
        exit,
    }
}

/// The identity import journal below `$HOME` (S21 interaction): one line per
/// `--import` that may reach the provider, appended before the request is
/// sent. `uninstall-app.sh` binds its resume markers to this file's digest,
/// so a marker written before an import (which may have put key material
/// back) is never honoured afterwards. Codes and times only.
pub const IMPORT_JOURNAL: &str =
    "Library/Application Support/dev.aegis.macos/identity-import-journal";

/// The stdout line when the import journal could not be appended: nothing
/// was sent (exit 66).
pub const JOURNAL_REFUSED_LINE: &str = "import_result=not_sent manifest_match=false source=kept";

/// The stderr code beside `JOURNAL_REFUSED_LINE`.
pub const JOURNAL_REFUSED: &str = "import_journal_unwritable";

/// Append one import attempt to `home`'s `IMPORT_JOURNAL`: its directory is
/// created 0700, the journal 0600; a link, a non-regular file, a file of
/// another user or one with another link is refused. Any failure means the
/// import must not be sent.
pub fn record_import_attempt(home: &Path) -> std::io::Result<()> {
    use std::{
        fs::{DirBuilder, OpenOptions},
        io::Write,
        os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    };
    let journal = home.join(IMPORT_JOURNAL);
    let Some(parent) = journal.parent() else {
        return Err(std::io::Error::other("import journal has no directory"));
    };
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)?;
    let mut file = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&journal)?;
    let meta = file.metadata()?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if !meta.is_file() || meta.uid() != euid || meta.nlink() != 1 || meta.mode() & 0o077 != 0 {
        return Err(std::io::Error::other("import journal refused"));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    writeln!(
        file,
        "import_attempt unix_ns={now} pid={}",
        std::process::id()
    )?;
    file.sync_all()
}

#[cfg(test)]
#[path = "host_import_tests.rs"]
pub(crate) mod tests;
