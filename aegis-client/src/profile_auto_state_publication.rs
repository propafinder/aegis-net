//! PRIVATE UNAPPLIED: exact prior state singleton publication, Linux only.
//! Store owns sealed-stage/phase/original-generation authority; no source reread.
use serde::{Deserialize, Serialize};
use std::{fs::File, io};
const MAX_STATE_BYTES: usize = 16 * 1024 * 1024;
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NodeIdentity {
    pub(crate) dev: u64,
    pub(crate) ino: u64,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) links: u64,
    pub(crate) len: u64,
    pub(crate) modified: (i64, i64),
    pub(crate) changed: (i64, i64),
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StateReceipt {
    pub(crate) parent: NodeIdentity,
    pub(crate) file: NodeIdentity,
    pub(crate) private_sha256: [u8; 32],
}
/// Authenticated only by the Store's actual private intent/receipt chain, never
/// by JSON shape. No Debug, path/payload/hash output or receipt self-authentication.
pub(crate) enum PublishOutcome {
    ExistingUnchanged,
    Created(StateReceipt),
}
pub(crate) struct StateFailure {
    pub(crate) phase: &'static str,
    pub(crate) kind: io::ErrorKind,
    pub(crate) created: Option<Box<StateReceipt>>,
    pub(crate) pending_intent: Option<Box<StateReceipt>>,
}
impl std::fmt::Debug for StateFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateFailure")
            .field("phase", &self.phase)
            .field("kind", &self.kind)
            .field("created_receipt_retained", &self.created.is_some())
            .field("pending_intent_retained", &self.pending_intent.is_some())
            .finish()
    }
}
fn fail(phase: &'static str, error: io::Error) -> StateFailure {
    StateFailure {
        phase,
        kind: error.kind(),
        created: None,
        pending_intent: None,
    }
}
fn refuse(phase: &'static str) -> StateFailure {
    fail(phase, io::Error::from(io::ErrorKind::InvalidData))
}
pub(crate) enum DestinationDisposition {
    Absent,
    ExistingUnchanged,
}
/// Implemented only by Store-verified immutable input/prior-state/bytes; callers
/// must not implement this as an unvalidated public payload/hash adapter.
pub(crate) trait VerifiedStateBytes {
    fn revalidate(&self) -> io::Result<()>;
    fn bytes(&self) -> io::Result<&[u8]>;
}
/// Concrete Store checks admitted stage FD/header nonce, Custody phase, exact
/// original optional destination generation, prior-path migration condition,
/// service UID/GID and exact input hash before allowing publication.
/// Existing ancestry must be actually traversable by that admitted service;
/// the Store must refuse inaccessible existing paths rather than modify them.
/// Callback receipts are persisted root-private before any phase advancement.
pub(crate) trait StateAuthority {
    fn revalidate(&self) -> io::Result<()>;
    fn admit_destination(
        &self,
        anchor: &DestinationAnchor,
        stage: &dyn VerifiedStateBytes,
        service_uid: u32,
        service_gid: u32,
    ) -> io::Result<DestinationDisposition>;
    fn verify_existing_destination(&self, parent: &File) -> io::Result<()>;
    fn record_directory_intent(
        &self,
        parent: &NodeIdentity,
        name: &str,
        new_uid: u32,
        new_gid: u32,
        new_mode: u32,
    ) -> io::Result<()>;
    fn record_directory_created(
        &self,
        parent: &NodeIdentity,
        name: &str,
        created: &NodeIdentity,
    ) -> io::Result<()>;
    fn record_publish_intent(&self, intent: &StateReceipt) -> io::Result<()>;
    fn record_created(&self, receipt: &StateReceipt) -> io::Result<()>;
    /// Must reject capture_started/native recovery, wrong phase/nonce/record and
    /// any receipt not authenticated by this exact Store's own successful publish.
    fn admit_rollback(&self, receipt: &StateReceipt) -> io::Result<()>;
    fn record_retirement_intent(
        &self,
        receipt: &StateReceipt,
        retirement_name: &str,
    ) -> io::Result<()>;
    fn record_retired(
        &self,
        receipt: &StateReceipt,
        retirement_name: &str,
        actual: &NodeIdentity,
    ) -> io::Result<()>;
}
/// Store supplies a held no-follow admitted nearest ancestor and bounded NORMAL
/// missing suffix from the original optional generation. This module does not
/// reopen or blindly recapture source/destination pathnames.
pub(crate) struct DestinationAnchor {
    pub(crate) directory: File,
    pub(crate) missing_suffix: Vec<String>,
    pub(crate) expected_directory: NodeIdentity,
}
impl DestinationAnchor {
    pub(crate) fn new(directory: File, missing_suffix: Vec<String>) -> io::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            linux::anchor(directory, missing_suffix)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (directory, missing_suffix);
            Err(io::Error::from(io::ErrorKind::Unsupported))
        }
    }
}
pub(crate) fn publish_prior_state_if_absent(
    authority: &dyn StateAuthority,
    stage: &dyn VerifiedStateBytes,
    anchor: DestinationAnchor,
    retirement: &File,
    service_uid: u32,
    service_gid: u32,
) -> Result<PublishOutcome, StateFailure> {
    #[cfg(target_os = "linux")]
    {
        linux::publish(
            authority,
            stage,
            anchor,
            retirement,
            service_uid,
            service_gid,
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (
            authority,
            stage,
            anchor,
            retirement,
            service_uid,
            service_gid,
        );
        Err(fail(
            "Linux state publication required",
            io::Error::from(io::ErrorKind::Unsupported),
        ))
    }
}
/// Retains the exact created inode in root-private same-filesystem custody.
/// Service-writable parent cannot support inode-conditional atomic retirement;
/// refuse and retain stage/state rather than rename/unlink an unrelated object.
pub(crate) fn retire_owned_created_state(
    authority: &dyn StateAuthority,
    parent: &File,
    retirement: &File,
    name: &str,
    receipt: &StateReceipt,
) -> Result<(), StateFailure> {
    #[cfg(target_os = "linux")]
    {
        linux::retire(authority, parent, retirement, name, receipt)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (authority, parent, retirement, name, receipt);
        Err(fail(
            "Linux state retirement required",
            io::Error::from(io::ErrorKind::Unsupported),
        ))
    }
}
#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        io::Write,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::fs::MetadataExt,
        },
    };
    fn identity(f: &File) -> io::Result<NodeIdentity> {
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
    fn same_directory(a: &NodeIdentity, b: &NodeIdentity) -> bool {
        a.dev == b.dev && a.ino == b.ino && a.mode == b.mode && a.uid == b.uid && a.gid == b.gid
    }
    fn directory(f: &File, uid: Option<u32>, private: bool) -> io::Result<NodeIdentity> {
        let n = identity(f)?;
        if n.mode & libc::S_IFMT != libc::S_IFDIR
            || n.mode & if private { 0o077 } else { 0o022 } != 0
            || uid.is_some_and(|u| n.uid != u)
        {
            return Err(io::Error::from(io::ErrorKind::PermissionDenied));
        }
        Ok(n)
    }
    fn component(s: &str) -> io::Result<CString> {
        if s.is_empty() || s == "." || s == ".." || s.len() > 255 || s.contains('/') {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        CString::new(s).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    }
    fn state_name() -> CString {
        CString::new("state.json").expect("static state leaf")
    }
    fn open_named(parent: &File, name: &CString) -> io::Result<File> {
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(raw) })
    }
    pub(super) fn anchor(directory_fd: File, suffix: Vec<String>) -> io::Result<DestinationAnchor> {
        if suffix.len() > 8 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        for part in &suffix {
            component(part)?;
        }
        let expected_directory = directory(&directory_fd, None, false)?;
        Ok(DestinationAnchor {
            directory: directory_fd,
            missing_suffix: suffix,
            expected_directory,
        })
    }
    pub(super) fn publish(
        authority: &dyn StateAuthority,
        stage: &dyn VerifiedStateBytes,
        anchor: DestinationAnchor,
        retirement: &File,
        uid: u32,
        gid: u32,
    ) -> Result<PublishOutcome, StateFailure> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(refuse("root state publication required"));
        }
        authority
            .revalidate()
            .map_err(|e| fail("Store authority", e))?;
        stage
            .revalidate()
            .map_err(|e| fail("sealed state bytes", e))?;
        let disposition = authority
            .admit_destination(&anchor, stage, uid, gid)
            .map_err(|e| fail("original state generation", e))?;
        let now = directory(&anchor.directory, None, false)
            .map_err(|e| fail("destination ancestor", e))?;
        if !same_directory(&anchor.expected_directory, &now) {
            return Err(refuse("destination ancestor changed"));
        }
        let mut parent = anchor.directory;
        if matches!(disposition, DestinationDisposition::ExistingUnchanged) {
            if !anchor.missing_suffix.is_empty() {
                return Err(refuse("existing state missing ancestry mismatch"));
            }
            authority
                .verify_existing_destination(&parent)
                .map_err(|e| fail("existing state generation", e))?;
            authority
                .revalidate()
                .map_err(|e| fail("Store authority", e))?;
            return Ok(PublishOutcome::ExistingUnchanged);
        }
        let retirement_id =
            directory(retirement, Some(0), true).map_err(|e| fail("retirement custody", e))?;
        if retirement_id.dev != now.dev {
            return Err(fail(
                "retirement filesystem mismatch",
                io::Error::from_raw_os_error(libc::EXDEV),
            ));
        }
        let missing_count = anchor.missing_suffix.len();
        for (index, part) in anchor.missing_suffix.into_iter().enumerate() {
            let p =
                directory(&parent, None, false).map_err(|e| fail("missing directory parent", e))?;
            if p.uid != 0 {
                return Err(refuse(
                    "new directories require admitted administrator parent",
                ));
            }
            let (new_uid, new_gid, new_mode) = if index + 1 == missing_count {
                (uid, gid, 0o700)
            } else {
                (0, 0, 0o755)
            };
            authority
                .record_directory_intent(&p, &part, new_uid, new_gid, new_mode)
                .map_err(|e| fail("directory intent", e))?;
            let leaf = component(&part).map_err(|e| fail("directory component", e))?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), leaf.as_ptr(), 0o700) } != 0 {
                return Err(fail(
                    "new directory no-overwrite",
                    io::Error::last_os_error(),
                ));
            }
            let raw = unsafe {
                libc::openat(
                    parent.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(fail("new directory handle", io::Error::last_os_error()));
            }
            let child = unsafe { File::from_raw_fd(raw) };
            let initial =
                directory(&child, Some(0), true).map_err(|e| fail("new directory custody", e))?;
            // Only the freshly-created held inode is modified. Existing directories
            // are never chmod/chowned; intermediate ancestry becomes traversable and
            // final state directory is private to the admitted service account.
            if unsafe { libc::fchown(child.as_raw_fd(), new_uid, new_gid) } != 0 {
                return Err(fail("new directory ownership", io::Error::last_os_error()));
            }
            if unsafe { libc::fchmod(child.as_raw_fd(), new_mode) } != 0 {
                return Err(fail("new directory mode", io::Error::last_os_error()));
            }
            let n = directory(&child, Some(new_uid), index + 1 == missing_count)
                .map_err(|e| fail("new directory final custody", e))?;
            if n.dev != initial.dev
                || n.ino != initial.ino
                || n.gid != new_gid
                || n.mode & 0o777 != new_mode
            {
                return Err(refuse("new directory generation mismatch"));
            }
            child
                .sync_all()
                .map_err(|e| fail("new directory attributes sync", e))?;
            parent
                .sync_all()
                .map_err(|e| fail("directory entry sync", e))?;
            authority
                .record_directory_created(&p, &part, &n)
                .map_err(|e| fail("directory receipt", e))?;
            parent = child;
        }
        let parent_id = directory(&parent, None, false).map_err(|e| fail("state parent", e))?;
        if parent_id.uid != 0 && parent_id.uid != uid {
            return Err(refuse("state parent role"));
        }
        if parent_id.dev != retirement_id.dev {
            return Err(fail(
                "retirement filesystem mismatch",
                io::Error::from_raw_os_error(libc::EXDEV),
            ));
        }
        match open_named(&parent, &state_name()) {
            Ok(_) => return Err(refuse("unexpected state already exists")),
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {}
            Err(e) => return Err(fail("state absence", e)),
        }
        stage
            .revalidate()
            .map_err(|e| fail("sealed state bytes", e))?;
        let bytes = stage.bytes().map_err(|e| fail("sealed state bytes", e))?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(refuse("bounded prior state required"));
        }
        let dot = CString::new(".").expect("static dot");
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                dot.as_ptr(),
                libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600,
            )
        };
        if raw < 0 {
            return Err(fail(
                "protected O_TMPFILE unavailable",
                io::Error::last_os_error(),
            ));
        }
        let mut file = unsafe { File::from_raw_fd(raw) };
        file.write_all(bytes).map_err(|e| fail("state write", e))?;
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(fail(
                "new state inode ownership",
                io::Error::last_os_error(),
            ));
        }
        file.sync_all()
            .map_err(|e| fail("new state inode sync", e))?;
        use sha2::Digest;
        let hash: [u8; 32] = sha2::Sha256::digest(bytes).into();
        let intent = StateReceipt {
            parent: parent_id.clone(),
            file: identity(&file).map_err(|e| fail("new state identity", e))?,
            private_sha256: hash,
        };
        stage
            .revalidate()
            .map_err(|e| fail("sealed state bytes", e))?;
        authority
            .revalidate()
            .map_err(|e| fail("Store authority", e))?;
        authority
            .record_publish_intent(&intent)
            .map_err(|e| fail("state intent", e))?;
        let empty = CString::new("").expect("static empty");
        if unsafe {
            libc::linkat(
                file.as_raw_fd(),
                empty.as_ptr(),
                parent.as_raw_fd(),
                state_name().as_ptr(),
                libc::AT_EMPTY_PATH,
            )
        } != 0
        {
            return Err(fail("state link no-overwrite", io::Error::last_os_error()));
        }
        let published = match identity(&file) {
            Ok(n) => n,
            Err(e) => {
                return Err(StateFailure {
                    phase: "linked state identity unavailable; pending intent retained",
                    kind: e.kind(),
                    created: None,
                    pending_intent: Some(Box::new(intent)),
                })
            }
        };
        if published.dev != intent.file.dev
            || published.ino != intent.file.ino
            || published.mode != intent.file.mode
            || published.uid != intent.file.uid
            || published.gid != intent.file.gid
            || published.links != 1
            || published.len != intent.file.len
            || published.modified != intent.file.modified
        {
            return Err(StateFailure {
                phase: "linked state changed; pending intent retained",
                kind: io::ErrorKind::InvalidData,
                created: None,
                pending_intent: Some(Box::new(intent)),
            });
        }
        let receipt = StateReceipt {
            parent: parent_id,
            file: published,
            private_sha256: hash,
        };
        // Any failure after link retains its durable pending intent. Once post-link
        // identity is verified it also carries the exact created receipt; unverified
        // metadata never becomes Created. Never delete or adopt another object.
        let finish = (|| -> io::Result<()> {
            let named = open_named(&parent, &state_name())?;
            if identity(&named)? != receipt.file {
                return Err(io::Error::from(io::ErrorKind::InvalidData));
            }
            parent.sync_all()?;
            authority.record_created(&receipt)?;
            Ok(())
        })();
        if let Err(error) = finish {
            return Err(StateFailure {
                phase: "linked state receipt not committed",
                kind: error.kind(),
                created: Some(Box::new(receipt)),
                pending_intent: Some(Box::new(intent)),
            });
        }
        Ok(PublishOutcome::Created(receipt))
    }
    pub(super) fn retire(
        authority: &dyn StateAuthority,
        parent: &File,
        custody: &File,
        name: &str,
        receipt: &StateReceipt,
    ) -> Result<(), StateFailure> {
        if unsafe { libc::geteuid() } != 0 {
            return Err(refuse("root state retirement required"));
        }
        authority
            .revalidate()
            .map_err(|e| fail("Store rollback authority", e))?;
        authority
            .admit_rollback(receipt)
            .map_err(|e| fail("owned state receipt admission", e))?;
        let p = directory(parent, Some(0), true)
            .map_err(|e| fail("unsafe rollback parent; retain state and stage", e))?;
        let c = directory(custody, Some(0), true).map_err(|e| fail("retirement custody", e))?;
        if !same_directory(&p, &receipt.parent) {
            return Err(refuse("published parent changed"));
        }
        if p.dev != c.dev {
            return Err(fail(
                "retirement filesystem mismatch",
                io::Error::from_raw_os_error(libc::EXDEV),
            ));
        }
        let leaf = component(name).map_err(|e| fail("retirement component", e))?;
        let held =
            open_named(parent, &state_name()).map_err(|e| fail("owned state namespace", e))?;
        if identity(&held).map_err(|e| fail("owned state identity", e))? != receipt.file {
            return Err(refuse("created state changed; retain state and stage"));
        }
        authority
            .record_retirement_intent(receipt, name)
            .map_err(|e| fail("retirement intent", e))?;
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent.as_raw_fd(),
                state_name().as_ptr(),
                custody.as_raw_fd(),
                leaf.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } != 0
        {
            return Err(fail(
                "retained retirement no-overwrite",
                io::Error::last_os_error(),
            ));
        }
        let retained = open_named(custody, &leaf).map_err(|e| fail("retained state handle", e))?;
        let actual = identity(&retained).map_err(|e| fail("retained state identity", e))?;
        // Rename can alter ctime, but never permits a different inode, content size,
        // owner/mode or modified-time generation. Keep mismatches retained, not restored.
        if actual.dev != receipt.file.dev
            || actual.ino != receipt.file.ino
            || actual.mode != receipt.file.mode
            || actual.uid != receipt.file.uid
            || actual.gid != receipt.file.gid
            || actual.links != receipt.file.links
            || actual.len != receipt.file.len
            || actual.modified != receipt.file.modified
        {
            return Err(refuse("retained state generation mismatch"));
        }
        parent
            .sync_all()
            .map_err(|e| fail("retirement parent sync", e))?;
        custody
            .sync_all()
            .map_err(|e| fail("retirement custody sync", e))?;
        authority
            .record_retired(receipt, name, &actual)
            .map_err(|e| fail("retired receipt", e))?;
        Ok(())
    }
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{cell::RefCell, fs, os::unix::fs::PermissionsExt};
    struct Stage(Vec<u8>);
    impl VerifiedStateBytes for Stage {
        fn revalidate(&self) -> io::Result<()> {
            Ok(())
        }
        fn bytes(&self) -> io::Result<&[u8]> {
            Ok(&self.0)
        }
    }
    struct Auth {
        events: RefCell<Vec<&'static str>>,
        existing: bool,
        deny: bool,
    }
    impl StateAuthority for Auth {
        fn revalidate(&self) -> io::Result<()> {
            if self.deny {
                Err(io::Error::from(io::ErrorKind::PermissionDenied))
            } else {
                Ok(())
            }
        }
        fn admit_destination(
            &self,
            _: &DestinationAnchor,
            _: &dyn VerifiedStateBytes,
            _: u32,
            _: u32,
        ) -> io::Result<DestinationDisposition> {
            self.revalidate()?;
            Ok(if self.existing {
                DestinationDisposition::ExistingUnchanged
            } else {
                DestinationDisposition::Absent
            })
        }
        fn verify_existing_destination(&self, p: &File) -> io::Result<()> {
            self.events.borrow_mut().push("existing");
            let name = std::ffi::CString::new("state.json").unwrap();
            if unsafe {
                libc::faccessat(
                    std::os::fd::AsRawFd::as_raw_fd(p),
                    name.as_ptr(),
                    libc::F_OK,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }
        fn record_directory_intent(
            &self,
            _: &NodeIdentity,
            _: &str,
            _: u32,
            _: u32,
            _: u32,
        ) -> io::Result<()> {
            self.events.borrow_mut().push("dir-intent");
            Ok(())
        }
        fn record_directory_created(
            &self,
            _: &NodeIdentity,
            _: &str,
            _: &NodeIdentity,
        ) -> io::Result<()> {
            self.events.borrow_mut().push("dir-receipt");
            Ok(())
        }
        fn record_publish_intent(&self, _: &StateReceipt) -> io::Result<()> {
            self.events.borrow_mut().push("intent");
            Ok(())
        }
        fn record_created(&self, _: &StateReceipt) -> io::Result<()> {
            self.events.borrow_mut().push("receipt");
            Ok(())
        }
        fn admit_rollback(&self, _: &StateReceipt) -> io::Result<()> {
            self.revalidate()
        }
        fn record_retirement_intent(&self, _: &StateReceipt, _: &str) -> io::Result<()> {
            self.events.borrow_mut().push("retire-intent");
            Ok(())
        }
        fn record_retired(&self, _: &StateReceipt, _: &str, _: &NodeIdentity) -> io::Result<()> {
            self.events.borrow_mut().push("retired");
            Ok(())
        }
    }
    fn dir() -> tempfile::TempDir {
        let d = tempfile::tempdir().unwrap();
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o700)).unwrap();
        d
    }
    fn auth(existing: bool) -> Auth {
        Auth {
            events: RefCell::new(Vec::new()),
            existing,
            deny: false,
        }
    }
    #[test]
    fn malformed_suffix_and_unsafe_parent_refuse_without_namespace_mutation() {
        let d = dir();
        assert!(DestinationAnchor::new(File::open(d.path()).unwrap(), vec!["..".into()]).is_err());
        assert!(DestinationAnchor::new(File::open(d.path()).unwrap(), vec!["a/b".into()]).is_err());
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(DestinationAnchor::new(File::open(d.path()).unwrap(), vec![]).is_err());
        assert!(!d.path().join("state.json").exists());
    }
    #[test]
    fn root_gated_actual_singleton_nooverwrite_and_retained_retirement() {
        let d = dir();
        let r = dir();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let a = auth(false);
        let stage = Stage(b"synthetic state".to_vec());
        let anchor = DestinationAnchor::new(File::open(d.path()).unwrap(), vec![]).unwrap();
        let result = publish_prior_state_if_absent(
            &a,
            &stage,
            anchor,
            &File::open(r.path()).unwrap(),
            uid,
            gid,
        );
        if uid != 0 {
            assert!(result.is_err());
            assert!(!d.path().join("state.json").exists());
            return;
        }
        let PublishOutcome::Created(receipt) = result.unwrap() else {
            panic!("new state required")
        };
        assert!(fs::read(d.path().join("state.json")).unwrap() == b"synthetic state");
        assert!(*a.events.borrow() == vec!["intent", "receipt"]);
        let before = fs::read(d.path().join("state.json")).unwrap();
        let existing = auth(true);
        let anchor = DestinationAnchor::new(File::open(d.path()).unwrap(), vec![]).unwrap();
        assert!(matches!(
            publish_prior_state_if_absent(
                &existing,
                &Stage(b"different".to_vec()),
                anchor,
                &File::open(r.path()).unwrap(),
                uid,
                gid
            )
            .unwrap(),
            PublishOutcome::ExistingUnchanged
        ));
        assert!(fs::read(d.path().join("state.json")).unwrap() == before);
        retire_owned_created_state(
            &a,
            &File::open(d.path()).unwrap(),
            &File::open(r.path()).unwrap(),
            "retained",
            &receipt,
        )
        .unwrap();
        assert!(!d.path().join("state.json").exists());
        assert!(fs::read(r.path().join("retained")).unwrap() == before);
    }
    #[test]
    fn root_gated_existing_or_substituted_inode_never_overwritten_or_retired() {
        let d = dir();
        let r = dir();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        fs::write(d.path().join("state.json"), b"existing").unwrap();
        let a = auth(false);
        let anchor = DestinationAnchor::new(File::open(d.path()).unwrap(), vec![]).unwrap();
        assert!(publish_prior_state_if_absent(
            &a,
            &Stage(b"new".to_vec()),
            anchor,
            &File::open(r.path()).unwrap(),
            uid,
            gid
        )
        .is_err());
        assert!(fs::read(d.path().join("state.json")).unwrap() == b"existing");
        if uid != 0 {
            return;
        }
        fs::remove_file(d.path().join("state.json")).unwrap();
        let anchor = DestinationAnchor::new(File::open(d.path()).unwrap(), vec![]).unwrap();
        let PublishOutcome::Created(receipt) = publish_prior_state_if_absent(
            &a,
            &Stage(b"owned".to_vec()),
            anchor,
            &File::open(r.path()).unwrap(),
            uid,
            gid,
        )
        .unwrap() else {
            panic!("created required")
        };
        fs::rename(d.path().join("state.json"), d.path().join("owned-old")).unwrap();
        fs::write(d.path().join("state.json"), b"foreign").unwrap();
        assert!(retire_owned_created_state(
            &a,
            &File::open(d.path()).unwrap(),
            &File::open(r.path()).unwrap(),
            "retained",
            &receipt
        )
        .is_err());
        assert!(fs::read(d.path().join("state.json")).unwrap() == b"foreign");
        assert!(!r.path().join("retained").exists());
    }
    #[test]
    fn root_gated_service_parent_publish_is_supported_but_unsafe_retirement_refuses() {
        let d = dir();
        let r = dir();
        let caller = unsafe { libc::geteuid() };
        if caller != 0 {
            return;
        }
        let service = 65520u32;
        use std::os::unix::fs::MetadataExt;
        let path = std::ffi::CString::new({
            use std::os::unix::ffi::OsStrExt;
            d.path().as_os_str().as_bytes()
        })
        .unwrap();
        assert!(unsafe { libc::chown(path.as_ptr(), service, service) } == 0);
        let a = auth(false);
        let anchor = DestinationAnchor::new(File::open(d.path()).unwrap(), vec![]).unwrap();
        let PublishOutcome::Created(receipt) = publish_prior_state_if_absent(
            &a,
            &Stage(b"service state".to_vec()),
            anchor,
            &File::open(r.path()).unwrap(),
            service,
            service,
        )
        .unwrap() else {
            panic!("created required")
        };
        assert!(fs::metadata(d.path().join("state.json")).unwrap().uid() == service);
        assert!(retire_owned_created_state(
            &a,
            &File::open(d.path()).unwrap(),
            &File::open(r.path()).unwrap(),
            "retained",
            &receipt
        )
        .is_err());
        assert!(fs::read(d.path().join("state.json")).unwrap() == b"service state");
        assert!(!r.path().join("retained").exists());
    }
    #[test]
    fn root_gated_missing_suffix_creation_has_intents_and_existing_directory_refusal() {
        let d = dir();
        let r = dir();
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        let a = auth(false);
        let anchor = DestinationAnchor::new(
            File::open(d.path()).unwrap(),
            vec!["missing".into(), "state-dir".into()],
        )
        .unwrap();
        let result = publish_prior_state_if_absent(
            &a,
            &Stage(b"synthetic".to_vec()),
            anchor,
            &File::open(r.path()).unwrap(),
            uid,
            gid,
        );
        if uid != 0 {
            assert!(result.is_err());
            assert!(!d.path().join("missing").exists());
            return;
        }
        assert!(matches!(result.unwrap(), PublishOutcome::Created(_)));
        assert!(
            *a.events.borrow()
                == vec![
                    "dir-intent",
                    "dir-receipt",
                    "dir-intent",
                    "dir-receipt",
                    "intent",
                    "receipt"
                ]
        );
        assert!(fs::read(d.path().join("missing/state-dir/state.json")).unwrap() == b"synthetic");
        let anchor =
            DestinationAnchor::new(File::open(d.path()).unwrap(), vec!["missing".into()]).unwrap();
        assert!(publish_prior_state_if_absent(
            &auth(false),
            &Stage(b"foreign".to_vec()),
            anchor,
            &File::open(r.path()).unwrap(),
            uid,
            gid
        )
        .is_err());
        assert!(!d.path().join("missing/state.json").exists());
    }

    #[test]
    fn root_gated_missing_suffix_nonroot_service_can_traverse_and_read_actual_state() {
        // Only synthetic newly-owned paths under traversable root /tmp; no permissions
        // changes to existing ancestry and no private payloads are exposed.
        let d = tempfile::Builder::new()
            .prefix("aegis-state-access-")
            .tempdir_in("/tmp")
            .unwrap();
        let r = dir();
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let service = 65520u32;
        fs::set_permissions(d.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let a = auth(false);
        let anchor = DestinationAnchor::new(
            File::open(d.path()).unwrap(),
            vec!["intermediate".into(), "state-dir".into()],
        )
        .unwrap();
        assert!(matches!(
            publish_prior_state_if_absent(
                &a,
                &Stage(b"synthetic private state".to_vec()),
                anchor,
                &File::open(r.path()).unwrap(),
                service,
                service
            )
            .unwrap(),
            PublishOutcome::Created(_)
        ));
        use std::os::unix::fs::MetadataExt;
        let middle = fs::metadata(d.path().join("intermediate")).unwrap();
        let final_dir = fs::metadata(d.path().join("intermediate/state-dir")).unwrap();
        assert!(middle.uid() == 0 && middle.gid() == 0 && middle.mode() & 0o777 == 0o755);
        assert!(
            final_dir.uid() == service
                && final_dir.gid() == service
                && final_dir.mode() & 0o777 == 0o700
        );
        let target = d.path().join("intermediate/state-dir/state.json");
        assert!(fs::metadata(&target).unwrap().uid() == service);
        use std::os::unix::ffi::OsStrExt;
        let target = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            // After fork use only bounded raw syscalls and fixed stack memory. No Rust
            // allocation, test harness, inherited root groups or privilege on reads.
            let dropped = unsafe { libc::setgroups(0, std::ptr::null()) } == 0
                && unsafe { libc::setgid(service) } == 0
                && unsafe { libc::setuid(service) } == 0;
            let fd = if dropped {
                unsafe {
                    libc::open(
                        target.as_ptr(),
                        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
                    )
                }
            } else {
                -1
            };
            let mut buffer = [0u8; 64];
            let mut used = 0usize;
            let mut eof = false;
            let mut good = fd >= 0;
            if fd >= 0 {
                for _ in 0..8 {
                    let n = unsafe {
                        libc::read(
                            fd,
                            buffer.as_mut_ptr().add(used).cast(),
                            buffer.len() - used,
                        )
                    };
                    if n == 0 {
                        eof = true;
                        break;
                    }
                    if n < 0 {
                        if unsafe { *libc::__errno_location() } == libc::EINTR {
                            continue;
                        }
                        good = false;
                        break;
                    }
                    used += n as usize;
                    if used == buffer.len() {
                        good = false;
                        break;
                    }
                }
                unsafe { libc::close(fd) };
            }
            let expected = b"synthetic private state";
            good = good && eof && used == expected.len() && buffer[..used] == expected[..];
            unsafe { libc::_exit(if good { 0 } else { 101 }) }
        }
        struct OwnedChild {
            pid: libc::pid_t,
            unreaped: bool,
            cleanup_attempted: bool,
            custody_lost: bool,
        }
        impl OwnedChild {
            fn observe(&mut self) -> io::Result<Option<i32>> {
                let mut status = 0;
                let n = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
                if n == self.pid {
                    self.unreaped = false;
                    return Ok(Some(status));
                }
                if n == 0 {
                    return Ok(None);
                }
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(libc::ECHILD) {
                    self.custody_lost = true;
                    self.unreaped = false;
                }
                Err(e)
            }
            fn cleanup(&mut self) -> bool {
                if self.custody_lost {
                    return false;
                }
                if !self.unreaped {
                    return true;
                }
                if self.cleanup_attempted {
                    return false;
                }
                self.cleanup_attempted = true;
                let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(2);
                let mut signalled = false;
                while std::time::Instant::now() < cutoff {
                    match self.observe() {
                        Ok(Some(_)) => return true,
                        Ok(None) => {
                            if !signalled {
                                unsafe { libc::kill(self.pid, libc::SIGKILL) };
                                signalled = true;
                            }
                        }
                        Err(e) => {
                            if e.raw_os_error() == Some(libc::ECHILD) {
                                return false;
                            } /* EINTR/other failures retry within same bound; never signal on unknown observation. */
                        }
                    }
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                false
            }
        }
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if self.unreaped && !self.cleanup_attempted {
                    let _ = self.cleanup();
                }
            }
        }
        let mut owned = OwnedChild {
            pid: child,
            unreaped: true,
            cleanup_attempted: false,
            custody_lost: false,
        };
        let cutoff = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match owned.observe() {
                Ok(Some(status)) => {
                    assert!(libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0);
                    break;
                }
                Ok(None) => {}
                Err(e) if e.raw_os_error() == Some(libc::EINTR) => {}
                Err(_) => {
                    let confirmed = owned.cleanup();
                    panic!("owned read child observation failed; cleanup confirmed={confirmed}");
                }
            }
            if std::time::Instant::now() >= cutoff {
                let confirmed = owned.cleanup();
                panic!("owned read child timed out; cleanup confirmed={confirmed}");
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}
