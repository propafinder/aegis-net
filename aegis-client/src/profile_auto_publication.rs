//! PRIVATE UNAPPLIED Linux-only atomic configuration publication.
//! No network/service/binary operation. Caller supplies owned captured bytes;
//! originals are inspected by metadata only. A durable intent must be synced
//! before rename. Interrupted operations require explicit reconciliation, never
//! automatic deletion of a possibly substituted backup.
#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::collections::{BTreeMap, BTreeSet};
    use std::ffi::{CStr, CString, OsStr};
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Component, Path, PathBuf};
    use zeroize::Zeroizing;

    pub(crate) type Result<T> = std::result::Result<T, &'static str>;
    const REFUSED: &str = "Administrative configuration publication refused";
    const MAX_DEPTH: usize = 8;
    const MAX_ENTRIES: usize = 1024;
    const MAX_FILE: usize = 16 * 1024 * 1024;
    const MAX_TREE: usize = 64 * 1024 * 1024;
    const SYSTEMD_DROPIN_TARGET: &str = "/etc/systemd/system/aegis-client.service.d";
    fn c(s: &OsStr) -> Result<CString> {
        CString::new(s.as_bytes()).map_err(|_| REFUSED)
    }
    fn fd(n: RawFd) -> Result<OwnedFd> {
        if n < 0 {
            Err(REFUSED)
        } else {
            Ok(unsafe { OwnedFd::from_raw_fd(n) })
        }
    }
    fn stat(n: RawFd) -> Result<libc::stat> {
        let mut s = std::mem::MaybeUninit::uninit();
        if unsafe { libc::fstat(n, s.as_mut_ptr()) } != 0 {
            return Err(REFUSED);
        }
        Ok(unsafe { s.assume_init() })
    }
    fn dir(parent: RawFd, name: &CStr) -> Result<OwnedFd> {
        fd(unsafe {
            libc::openat(
                parent,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })
    }
    fn absent() -> bool {
        std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT)
    }
    fn sync(n: RawFd) -> Result<()> {
        if unsafe { libc::fsync(n) } == 0 {
            Ok(())
        } else {
            Err(REFUSED)
        }
    }
    fn rename(parent: RawFd, from: &CStr, to: &CStr, flags: u32) -> Result<()> {
        if unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                parent,
                from.as_ptr(),
                parent,
                to.as_ptr(),
                flags,
            )
        } == 0
        {
            Ok(())
        } else {
            Err(REFUSED)
        }
    }
    fn relative(p: &Path) -> bool {
        let n = p.components().count();
        n > 0
            && n <= MAX_DEPTH
            && p.components().all(|x| matches!(x, Component::Normal(_)))
            && !p.as_os_str().as_bytes().contains(&0)
    }
    fn components(p: &Path) -> Result<Vec<CString>> {
        if !relative(p) {
            return Err(REFUSED);
        }
        p.components()
            .map(|x| match x {
                Component::Normal(n) => c(n),
                _ => Err(REFUSED),
            })
            .collect()
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct Identity {
        pub dev: u64,
        pub ino: u64,
    }
    fn identity(s: &libc::stat) -> Identity {
        Identity {
            dev: s.st_dev,
            ino: s.st_ino,
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Metadata {
        id: Identity,
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
    fn metadata(s: &libc::stat) -> Metadata {
        // Linux libc::nlink_t is u32 on aarch64 and u64 on x86_64.
        // Keep the serialized witness lossless on both architectures.
        #[allow(clippy::useless_conversion)]
        let links = u64::from(s.st_nlink);
        Metadata {
            id: identity(s),
            mode: s.st_mode,
            uid: s.st_uid,
            gid: s.st_gid,
            links,
            size: s.st_size,
            mtime: s.st_mtime,
            mtime_ns: s.st_mtime_nsec,
            ctime: s.st_ctime,
            ctime_ns: s.st_ctime_nsec,
        }
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    pub(crate) struct Generation {
        entries: BTreeMap<PathBuf, Metadata>,
    }
    impl Generation {
        /// Metadata captured with bytes must be compared to this witness before
        /// stage build and again through an active capture guard before rename.
        pub fn witness(&self) -> Result<Vec<u8>> {
            serde_json::to_vec(&self.entries).map_err(|_| REFUSED)
        }
        pub fn from_guarded_witness(
            target: &Path,
            bytes: &[u8],
            guard: &(impl CaptureGuard + ?Sized),
        ) -> Result<Self> {
            if bytes.len() > 4 * 1024 * 1024 {
                return Err(REFUSED);
            }
            let entries: BTreeMap<PathBuf, Metadata> =
                serde_json::from_slice(bytes).map_err(|_| REFUSED)?;
            if entries.is_empty()
                || entries.len() > 1025
                || !entries.contains_key(Path::new(""))
                || entries.iter().any(|(p, m)| {
                    (!p.as_os_str().is_empty() && !relative(p))
                        || !matches!(m.mode & libc::S_IFMT, libc::S_IFDIR | libc::S_IFREG)
                        || m.links == 0
                })
            {
                return Err(REFUSED);
            }
            let expected = Self { entries };
            guard.validate_captured_generation(target, Some(&expected))?;
            Ok(expected)
        }
        pub fn root_identity(&self) -> Result<Identity> {
            Ok(self.entries.get(Path::new("")).ok_or(REFUSED)?.id.clone())
        }
        #[cfg(test)]
        pub fn entry_count(&self) -> usize {
            self.entries.len()
        }
        #[cfg(test)]
        pub fn digest(&self) -> Result<String> {
            Ok(format!(
                "{:x}",
                Sha256::digest(serde_json::to_vec(&self.entries).map_err(|_| REFUSED)?)
            ))
        }
    }

    /// Caller implements this with its active byte-capture guard. There is no
    /// default/no-op implementation here: validate the same captured metadata
    /// and administrative stage chain both before build and before publication.
    pub(crate) trait CaptureGuard {
        fn validate_captured_generation(
            &self,
            target: &Path,
            expected: Option<&Generation>,
        ) -> Result<()>;
    }
    pub(crate) fn bind_captured_generation(
        target: &Target,
        expected: Option<&Generation>,
        guard: &(impl CaptureGuard + ?Sized),
    ) -> Result<()> {
        guard.validate_captured_generation(&target.path, expected)?;
        if target.inspect()?.as_ref() != expected {
            return Err(REFUSED);
        }
        Ok(())
    }
    /// Includes explicit empty directories. Intermediate directories are added
    /// exactly once. Duplicate/overlapping file paths are rejected.
    pub(crate) struct CapturedTree {
        files: BTreeMap<PathBuf, Zeroizing<Vec<u8>>>,
        dirs: BTreeSet<PathBuf>,
    }
    impl CapturedTree {
        pub fn new(
            files: BTreeMap<PathBuf, Vec<u8>>,
            empty_dirs: BTreeSet<PathBuf>,
        ) -> Result<Self> {
            let mut dirs = empty_dirs;
            let mut total = 0usize;
            if dirs.iter().any(|p| !relative(p)) {
                return Err(REFUSED);
            }
            for (p, b) in &files {
                total = total.checked_add(b.len()).ok_or(REFUSED)?;
                if !relative(p) || b.len() > MAX_FILE || total > MAX_TREE || dirs.contains(p) {
                    return Err(REFUSED);
                }
                let mut ancestor = p.parent();
                while let Some(a) = ancestor {
                    if a.as_os_str().is_empty() {
                        break;
                    }
                    dirs.insert(a.to_path_buf());
                    ancestor = a.parent();
                }
            }
            // Explicit nested empty directories also require all ancestors.
            for p in dirs.clone() {
                let mut a = p.parent();
                while let Some(x) = a {
                    if x.as_os_str().is_empty() {
                        break;
                    }
                    dirs.insert(x.to_path_buf());
                    a = x.parent();
                }
            }
            if files.keys().any(|p| dirs.contains(p)) || files.len() + dirs.len() > MAX_ENTRIES {
                return Err(REFUSED);
            }
            Ok(Self {
                files: files
                    .into_iter()
                    .map(|(p, b)| (p, Zeroizing::new(b)))
                    .collect(),
                dirs,
            })
        }
    }
    struct Anchor {
        path: PathBuf,
        id: Identity,
    }
    /// Namespace authority: all ancestors are administrator-owned and have no
    /// group/other write bit. No lexical aliases, symlinks or canonicalization.
    pub(crate) struct Target {
        path: PathBuf,
        parent: OwnedFd,
        leaf: CString,
        anchors: Vec<Anchor>,
        admin: u32,
    }
    impl Target {
        pub fn open(path: &Path) -> Result<Self> {
            if !path.is_absolute()
                || path == Path::new("/")
                || path
                    .components()
                    .any(|x| !matches!(x, Component::RootDir | Component::Normal(_)))
                || path.as_os_str().as_bytes().contains(&0)
            {
                return Err(REFUSED);
            }
            let clean: PathBuf = path.components().collect();
            if clean.as_os_str().as_bytes() != path.as_os_str().as_bytes() {
                return Err(REFUSED);
            }
            let admin = unsafe { libc::geteuid() };
            let parent_path = path.parent().ok_or(REFUSED)?;
            let root = c(OsStr::new("/"))?;
            let mut parent = fd(unsafe {
                libc::open(
                    root.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            let mut prefix = PathBuf::from("/");
            let mut anchors = Vec::new();
            let s = stat(parent.as_raw_fd())?;
            // Non-root private tests admit the system root, but never a writable
            // ancestor. All non-root components must belong to the invocation.
            if s.st_uid != 0 || s.st_mode & 0o022 != 0 {
                return Err(REFUSED);
            }
            anchors.push(Anchor {
                path: prefix.clone(),
                id: identity(&s),
            });
            for part in parent_path.components() {
                if let Component::Normal(n) = part {
                    parent = dir(parent.as_raw_fd(), &c(n)?)?;
                    prefix.push(n);
                    let s = stat(parent.as_raw_fd())?;
                    let trusted_sticky_tmp = prefix == Path::new("/tmp")
                        && prefix != parent_path
                        && s.st_uid == 0
                        && s.st_mode & libc::S_ISVTX != 0;
                    if (s.st_uid != admin && s.st_uid != 0)
                        || (s.st_mode & 0o022 != 0 && !trusted_sticky_tmp)
                    {
                        return Err(REFUSED);
                    }
                    anchors.push(Anchor {
                        path: prefix.clone(),
                        id: identity(&s),
                    });
                }
            }
            let parent_stat = stat(parent.as_raw_fd())?;
            if parent_stat.st_uid != admin || parent_stat.st_mode & 0o022 != 0 {
                return Err(REFUSED);
            }
            let out = Self {
                path: path.to_path_buf(),
                parent,
                leaf: c(path.file_name().ok_or(REFUSED)?)?,
                anchors,
                admin,
            };
            out.revalidate_namespace()?;
            Ok(out)
        }
        #[cfg(test)]
        pub fn reject_overlap(&self, other: &Path) -> Result<()> {
            if self.path.starts_with(other) || other.starts_with(&self.path) {
                Err(REFUSED)
            } else {
                Ok(())
            }
        }
        fn revalidate_namespace(&self) -> Result<()> {
            // Reopen every ancestor from root and compare with held generation.
            let root = c(OsStr::new("/"))?;
            let mut f = fd(unsafe {
                libc::open(
                    root.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            })?;
            for (i, a) in self.anchors.iter().enumerate() {
                if i > 0 {
                    f = dir(f.as_raw_fd(), &c(a.path.file_name().ok_or(REFUSED)?)?)?;
                }
                let s = stat(f.as_raw_fd())?;
                let trusted_sticky_tmp = a.path == Path::new("/tmp")
                    && i + 1 < self.anchors.len()
                    && s.st_uid == 0
                    && s.st_mode & libc::S_ISVTX != 0;
                if identity(&s) != a.id
                    || (s.st_mode & 0o022 != 0 && !trusted_sticky_tmp)
                    || (s.st_uid != 0 && s.st_uid != self.admin)
                {
                    return Err(REFUSED);
                }
                if i + 1 == self.anchors.len() && s.st_uid != self.admin {
                    return Err(REFUSED);
                }
            }
            if identity(&stat(self.parent.as_raw_fd())?) != self.anchors.last().ok_or(REFUSED)?.id {
                return Err(REFUSED);
            }
            Ok(())
        }
        pub fn inspect(&self) -> Result<Option<Generation>> {
            self.revalidate_namespace()?;
            self.inspect_name(&self.leaf)
        }
        fn inspect_name(&self, name: &CStr) -> Result<Option<Generation>> {
            let f = match dir(self.parent.as_raw_fd(), name) {
                Ok(f) => f,
                Err(_) if absent() => return Ok(None),
                Err(e) => return Err(e),
            };
            let mut entries = BTreeMap::new();
            let mut total = 0usize;
            scan(f.as_raw_fd(), Path::new(""), 0, &mut entries, &mut total)?;
            Ok(Some(Generation { entries }))
        }
    }
    fn names(n: RawFd) -> Result<Vec<CString>> {
        // openat "." gives an independent directory offset; dup would share it.
        let dot = c(OsStr::new("."))?;
        let f = dir(n, &dot)?;
        let raw = std::os::fd::IntoRawFd::into_raw_fd(f);
        let stream = unsafe { libc::fdopendir(raw) };
        if stream.is_null() {
            unsafe { libc::close(raw) };
            return Err(REFUSED);
        }
        struct Stream(*mut libc::DIR);
        impl Drop for Stream {
            fn drop(&mut self) {
                unsafe { libc::closedir(self.0) };
            }
        }
        let guard = Stream(stream);
        let mut out = Vec::new();
        loop {
            unsafe { *libc::__errno_location() = 0 };
            let entry = unsafe { libc::readdir(guard.0) };
            if entry.is_null() {
                if std::io::Error::last_os_error().raw_os_error() != Some(0) {
                    return Err(REFUSED);
                }
                break;
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if name.to_bytes() != b"." && name.to_bytes() != b".." {
                out.push(name.to_owned());
                if out.len() > MAX_ENTRIES {
                    return Err(REFUSED);
                }
            }
        }
        out.sort();
        Ok(out)
    }
    fn scan(
        n: RawFd,
        path: &Path,
        depth: usize,
        entries: &mut BTreeMap<PathBuf, Metadata>,
        total: &mut usize,
    ) -> Result<()> {
        if depth > MAX_DEPTH || entries.len() > MAX_ENTRIES {
            return Err(REFUSED);
        }
        let before = stat(n)?;
        entries.insert(path.to_path_buf(), metadata(&before));
        let list = names(n)?;
        for name in &list {
            let mut s = std::mem::MaybeUninit::uninit();
            if unsafe { libc::fstatat(n, name.as_ptr(), s.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) }
                != 0
            {
                return Err(REFUSED);
            }
            let s = unsafe { s.assume_init() };
            let p = path.join(OsStr::from_bytes(name.to_bytes()));
            if entries.len() > MAX_ENTRIES {
                return Err(REFUSED);
            }
            match s.st_mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let child = dir(n, name)?;
                    if identity(&stat(child.as_raw_fd())?) != identity(&s) {
                        return Err(REFUSED);
                    }
                    scan(child.as_raw_fd(), &p, depth + 1, entries, total)?;
                }
                libc::S_IFREG => {
                    if s.st_nlink != 1 || s.st_size < 0 || s.st_size as usize > MAX_FILE {
                        return Err(REFUSED);
                    }
                    *total = total.checked_add(s.st_size as usize).ok_or(REFUSED)?;
                    if *total > MAX_TREE {
                        return Err(REFUSED);
                    }
                    entries.insert(p, metadata(&s));
                }
                _ => return Err(REFUSED),
            }
        }
        if names(n)? != list || metadata(&stat(n)?) != metadata(&before) {
            return Err(REFUSED);
        }
        Ok(())
    }
    fn set_new(n: RawFd, uid: u32, gid: u32, mode: u32) -> Result<()> {
        if unsafe { libc::geteuid() } != 0
            && (uid != unsafe { libc::geteuid() } || gid != unsafe { libc::getegid() })
        {
            return Err(REFUSED);
        }
        let before = stat(n)?;
        if unsafe { libc::fchown(n, uid, gid) } != 0 || unsafe { libc::fchmod(n, mode) } != 0 {
            return Err(REFUSED);
        }
        let after = stat(n)?;
        if identity(&before) != identity(&after)
            || before.st_nlink != after.st_nlink
            || before.st_mode & libc::S_IFMT != after.st_mode & libc::S_IFMT
            || after.st_uid != uid
            || after.st_gid != gid
            || after.st_mode & 0o7777 != mode
        {
            return Err(REFUSED);
        }
        Ok(())
    }
    fn random_name() -> CString {
        let bytes: [u8; 16] = rand::random();
        let mut s = String::from(".auto-config-");
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(s, "{b:02x}");
        }
        CString::new(s).expect("fixed ASCII")
    }
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum RootMode {
        ServiceConfig0750,
        AdministratorMetadata0700,
        RuntimeConfig0700,
        RuntimeConfig0750,
        RuntimeState0700,
        /// Only authenticated retained-state exchange; never Prepared creation.
        RetainedOriginalTree,
    }
    impl RootMode {
        fn mode(self) -> u32 {
            match self {
                // This sentinel is unreachable in metadata mutation paths.
                Self::RetainedOriginalTree => 0,
                Self::ServiceConfig0750 | Self::RuntimeConfig0750 => 0o750,
                Self::AdministratorMetadata0700
                | Self::RuntimeConfig0700
                | Self::RuntimeState0700 => 0o700,
            }
        }
    }
    #[derive(Clone, Copy, PartialEq, Eq)]
    pub(crate) enum ConfigLeafRole {
        Public,
        SystemdDropin,
        RuntimePrivate,
        AdministratorPrivate,
    }
    pub(crate) struct ConfigPolicy {
        pub runtime_uid: u32,
        pub runtime_gid: u32,
        pub root_policy: bool,
        pub leaves: BTreeMap<PathBuf, ConfigLeafRole>,
    }
    impl ConfigPolicy {
        fn attributes(&self, role: ConfigLeafRole) -> (u32, u32, u32) {
            match role {
                ConfigLeafRole::Public => (
                    0,
                    self.runtime_gid,
                    if self.root_policy { 0o600 } else { 0o640 },
                ),
                ConfigLeafRole::SystemdDropin => (0, 0, 0o644),
                ConfigLeafRole::RuntimePrivate => (self.runtime_uid, self.runtime_gid, 0o600),
                ConfigLeafRole::AdministratorPrivate => (0, 0, 0o600),
            }
        }
    }
    fn root_owned_config_tree_exact(tree: &Generation, target: &Path) -> Result<()> {
        for meta in tree.entries.values() {
            let mode = meta.mode & 0o7777;
            let valid = match meta.mode & libc::S_IFMT {
                libc::S_IFDIR => mode == 0o700,
                libc::S_IFREG if meta.links == 1 => {
                    mode == 0o600 || (target == Path::new(SYSTEMD_DROPIN_TARGET) && mode == 0o644)
                }
                _ => false,
            };
            if meta.uid != 0 || meta.gid != 0 || !valid {
                return Err(REFUSED);
            }
        }
        Ok(())
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct PublicationIntent {
        protocol: String,
        epoch: String,
        target: PathBuf,
        parent: Identity,
        stage: String,
        old: Option<GenerationWire>,
        new_root: Identity,
        new_tree: GenerationWire,
        service_uid: u32,
        service_gid: u32,
        root_mode: RootMode,
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct GenerationWire {
        entries: BTreeMap<PathBuf, Metadata>,
    }
    /// Receipt construction is private; JSON alone is never publication authority.
    pub(crate) struct PublicationReceipt {
        intent: PublicationIntent,
        current: Generation,
        root: OwnedFd,
        old_root: Option<OwnedFd>,
    }
    impl PublicationReceipt {
        pub fn intent(&self) -> &PublicationIntent {
            &self.intent
        }
        pub fn generation(&self) -> &Generation {
            &self.current
        }
    }
    #[derive(Clone, Debug, Serialize)]
    pub(crate) struct StageReceipt {
        pub target: PathBuf,
        pub parent: Identity,
        pub stage: String,
        pub root: Identity,
    }
    pub(crate) struct Prepared {
        target: Target,
        root: OwnedFd,
        stage: CString,
        expected: Option<Generation>,
        old_root: Option<OwnedFd>,
        new_dirs: Vec<OwnedFd>,
        new_files: Vec<OwnedFd>,
        uid: u32,
        gid: u32,
        root_mode: RootMode,
    }
    impl Prepared {
        #[cfg(test)]
        fn build(
            target: Target,
            expected: Option<Generation>,
            tree: &CapturedTree,
            uid: u32,
            gid: u32,
            preserve_stage: impl FnMut(&StageReceipt) -> Result<()>,
        ) -> Result<Self> {
            Self::build_policy(
                target,
                expected,
                tree,
                uid,
                gid,
                RootMode::ServiceConfig0750,
                preserve_stage,
            )
        }
        fn build_policy(
            target: Target,
            expected: Option<Generation>,
            tree: &CapturedTree,
            uid: u32,
            gid: u32,
            root_mode: RootMode,
            preserve_stage: impl FnMut(&StageReceipt) -> Result<()>,
        ) -> Result<Self> {
            Self::build_policy_inner(
                target,
                expected,
                tree,
                uid,
                gid,
                root_mode,
                preserve_stage,
                None,
            )
        }
        #[allow(clippy::too_many_arguments)]
        fn build_policy_inner(
            target: Target,
            expected: Option<Generation>,
            tree: &CapturedTree,
            uid: u32,
            gid: u32,
            root_mode: RootMode,
            mut preserve_stage: impl FnMut(&StageReceipt) -> Result<()>,
            mixed: Option<&ConfigPolicy>,
        ) -> Result<Self> {
            if root_mode == RootMode::RetainedOriginalTree {
                return Err(REFUSED);
            }
            if let Some(policy) = mixed {
                if policy
                    .leaves
                    .values()
                    .any(|role| *role == ConfigLeafRole::SystemdDropin)
                    && (!policy.root_policy
                        || policy.runtime_gid != 0
                        || target.path != Path::new(SYSTEMD_DROPIN_TARGET))
                {
                    return Err(REFUSED);
                }
                if unsafe { libc::geteuid() } != 0
                    || uid != 0
                    || gid != policy.runtime_gid
                    || policy.root_policy != (policy.runtime_uid == 0)
                    || policy.leaves.keys().ne(tree.files.keys())
                    || root_mode
                        != if policy.root_policy {
                            RootMode::RuntimeConfig0700
                        } else {
                            RootMode::RuntimeConfig0750
                        }
                {
                    return Err(REFUSED);
                }
            } else if matches!(
                root_mode,
                RootMode::RuntimeConfig0700 | RootMode::RuntimeConfig0750
            ) {
                return Err(REFUSED);
            }
            if root_mode == RootMode::AdministratorMetadata0700
                && (uid != 0 || gid != 0 || unsafe { libc::geteuid() } != 0)
            {
                return Err(REFUSED);
            }
            if target.inspect()? != expected {
                return Err(REFUSED);
            }
            if unsafe { libc::geteuid() } != 0
                && (uid != unsafe { libc::geteuid() } || gid != unsafe { libc::getegid() })
            {
                return Err(REFUSED);
            }
            let old_root = if expected.is_some() {
                Some(dir(target.parent.as_raw_fd(), &target.leaf)?)
            } else {
                None
            };
            if let (Some(f), Some(g)) = (&old_root, &expected) {
                if identity(&stat(f.as_raw_fd())?)
                    != g.entries.get(Path::new("")).ok_or(REFUSED)?.id
                {
                    return Err(REFUSED);
                }
            }
            let stage = random_name();
            if unsafe { libc::mkdirat(target.parent.as_raw_fd(), stage.as_ptr(), 0o700) } != 0 {
                return Err(REFUSED);
            }
            let root = dir(target.parent.as_raw_fd(), &stage)?;
            let root_stat = stat(root.as_raw_fd())?;
            if root_stat.st_uid != target.admin || root_stat.st_mode & 0o777 != 0o700 {
                return Err(REFUSED);
            }
            preserve_stage(&StageReceipt {
                target: target.path.clone(),
                parent: identity(&stat(target.parent.as_raw_fd())?),
                stage: stage.to_str().map_err(|_| REFUSED)?.into(),
                root: identity(&root_stat),
            })?;
            let mut out = Self {
                target,
                root,
                stage,
                expected,
                old_root,
                new_dirs: Vec::new(),
                new_files: Vec::new(),
                uid,
                gid,
                root_mode,
            };
            // Stage is private and parent is non-writable by the service user;
            // only fresh stage entries receive ownership/mode operations.
            for p in &tree.dirs {
                let parts = components(p)?;
                let parent = out.stage_parent(&parts[..parts.len() - 1])?;
                if unsafe {
                    libc::mkdirat(
                        parent.as_raw_fd(),
                        parts.last().ok_or(REFUSED)?.as_ptr(),
                        0o700,
                    )
                } != 0
                {
                    return Err(REFUSED);
                }
                out.new_dirs
                    .push(dir(parent.as_raw_fd(), parts.last().ok_or(REFUSED)?)?);
            }
            for (p, bytes) in &tree.files {
                let parts = components(p)?;
                let parent = out.stage_parent(&parts[..parts.len() - 1])?;
                let f = fd(unsafe {
                    libc::openat(
                        parent.as_raw_fd(),
                        parts.last().ok_or(REFUSED)?.as_ptr(),
                        libc::O_WRONLY
                            | libc::O_CREAT
                            | libc::O_EXCL
                            | libc::O_NOFOLLOW
                            | libc::O_CLOEXEC,
                        0o600,
                    )
                })?;
                let mut file = File::from(f);
                file.write_all(bytes.as_slice()).map_err(|_| REFUSED)?;
                file.sync_all().map_err(|_| REFUSED)?;
                out.new_files.push(file.into());
            }
            for ((path, _), f) in tree.files.iter().zip(&out.new_files) {
                let (file_uid, file_gid, file_mode) = match mixed {
                    Some(policy) => policy.attributes(*policy.leaves.get(path).ok_or(REFUSED)?),
                    None => (uid, gid, 0o600),
                };
                set_new(f.as_raw_fd(), file_uid, file_gid, file_mode)?;
                sync(f.as_raw_fd())?;
            }
            for d in out.new_dirs.iter().rev() {
                set_new(d.as_raw_fd(), uid, gid, root_mode.mode())?;
                sync(d.as_raw_fd())?;
            }
            sync(out.root.as_raw_fd())?;
            sync(out.target.parent.as_raw_fd())?;
            out.target.revalidate_namespace()?;
            if out.target.inspect()? != out.expected {
                return Err(REFUSED);
            }
            Ok(out)
        }
        #[cfg(test)]
        pub fn build_captured(
            target: Target,
            expected: Option<Generation>,
            tree: &CapturedTree,
            uid: u32,
            gid: u32,
            preserve_stage: impl FnMut(&StageReceipt) -> Result<()>,
            guard: &(impl CaptureGuard + ?Sized),
        ) -> Result<Self> {
            bind_captured_generation(&target, expected.as_ref(), guard)?;
            Self::build(target, expected, tree, uid, gid, preserve_stage)
        }
        // Eight arguments intentionally keep closed ownership/mode/guard and
        // persistence authority explicit; grouping them risks claimant defaults.
        #[allow(clippy::too_many_arguments)]
        pub fn build_policy_captured(
            target: Target,
            expected: Option<Generation>,
            tree: &CapturedTree,
            uid: u32,
            gid: u32,
            root_mode: RootMode,
            preserve_stage: impl FnMut(&StageReceipt) -> Result<()>,
            guard: &(impl CaptureGuard + ?Sized),
        ) -> Result<Self> {
            bind_captured_generation(&target, expected.as_ref(), guard)?;
            Self::build_policy(target, expected, tree, uid, gid, root_mode, preserve_stage)
        }
        pub fn build_runtime_config_captured(
            target: Target,
            expected: Option<Generation>,
            tree: &CapturedTree,
            policy: &ConfigPolicy,
            preserve_stage: impl FnMut(&StageReceipt) -> Result<()>,
            guard: &(impl CaptureGuard + ?Sized),
        ) -> Result<Self> {
            bind_captured_generation(&target, expected.as_ref(), guard)?;
            let mode = if policy.root_policy {
                RootMode::RuntimeConfig0700
            } else {
                RootMode::RuntimeConfig0750
            };
            Self::build_policy_inner(
                target,
                expected,
                tree,
                0,
                policy.runtime_gid,
                mode,
                preserve_stage,
                Some(policy),
            )
        }
        fn stage_parent(&self, parts: &[CString]) -> Result<OwnedFd> {
            let mut f = dir(self.root.as_raw_fd(), &c(OsStr::new("."))?)?;
            for p in parts {
                f = dir(f.as_raw_fd(), p)?;
            }
            Ok(f)
        }
        pub fn intent(&self) -> Result<PublicationIntent> {
            self.target.revalidate_namespace()?;
            if self.target.inspect()? != self.expected {
                return Err(REFUSED);
            }
            let root = stat(self.root.as_raw_fd())?;
            let named = dir(self.target.parent.as_raw_fd(), &self.stage)?;
            if identity(&stat(named.as_raw_fd())?) != identity(&root) {
                return Err(REFUSED);
            }
            Ok(PublicationIntent {
                protocol: "auto-config-publication-v1".into(),
                epoch: self.stage.to_str().map_err(|_| REFUSED)?.into(),
                target: self.target.path.clone(),
                parent: identity(&stat(self.target.parent.as_raw_fd())?),
                stage: self.stage.to_str().map_err(|_| REFUSED)?.into(),
                old: self.expected.as_ref().map(|g| GenerationWire {
                    entries: g.entries.clone(),
                }),
                new_root: identity(&root),
                new_tree: GenerationWire {
                    entries: self
                        .target
                        .inspect_name(&self.stage)?
                        .ok_or(REFUSED)?
                        .entries,
                },
                service_uid: self.uid,
                service_gid: self.gid,
                root_mode: self.root_mode,
            })
        }
        pub fn publish_captured(
            self,
            persist: impl FnMut(&PublicationIntent) -> Result<()>,
            guard: &(impl CaptureGuard + ?Sized),
        ) -> Result<PublicationReceipt> {
            bind_captured_generation(&self.target, self.expected.as_ref(), guard)?;
            self.publish(persist, |target, expected| {
                bind_captured_generation(target, expected, guard)
            })
        }
        /// persist must durably save/sync this intent and its phase. An error
        /// after rename leaves both trees untouched for reconciliation.
        fn publish(
            self,
            mut persist: impl FnMut(&PublicationIntent) -> Result<()>,
            pre_rename: impl FnOnce(&Target, Option<&Generation>) -> Result<()>,
        ) -> Result<PublicationReceipt> {
            let intent = self.intent()?;
            persist(&intent)?;
            // Validate active capture guard again AFTER intent persistence, before syscall.
            pre_rename(&self.target, self.expected.as_ref())?;
            if self.target.inspect()? != self.expected {
                return Err(REFUSED);
            }
            rename(
                self.target.parent.as_raw_fd(),
                &self.stage,
                &self.target.leaf,
                if self.expected.is_some() {
                    libc::RENAME_EXCHANGE
                } else {
                    libc::RENAME_NOREPLACE
                },
            )?;
            sync(self.target.parent.as_raw_fd())?;
            self.target.revalidate_namespace()?;
            let named = dir(self.target.parent.as_raw_fd(), &self.target.leaf)?;
            if identity(&stat(named.as_raw_fd())?) != intent.new_root {
                return Err(REFUSED);
            }
            // The displaced generation remains at stage; never delete it.
            if self.expected.is_some()
                && !same_displaced(
                    self.target.inspect_name(&self.stage)?.as_ref(),
                    self.expected.as_ref(),
                )
            {
                return Err(REFUSED);
            }
            set_new(
                self.root.as_raw_fd(),
                self.uid,
                self.gid,
                self.root_mode.mode(),
            )?;
            sync(self.root.as_raw_fd())?;
            let current = self.target.inspect()?.ok_or(REFUSED)?;
            if current.entries.get(Path::new("")).ok_or(REFUSED)?.id != intent.new_root {
                return Err(REFUSED);
            }
            let planned = Generation {
                entries: intent.new_tree.entries.clone(),
            };
            if !same_new(&current, &planned, self.uid, self.gid, self.root_mode) {
                return Err(REFUSED);
            }
            Ok(PublicationReceipt {
                intent,
                current,
                root: self.root,
                old_root: self.old_root,
            })
        }
    }
    /// Revalidates the descriptor-owned complete state generation and closed
    /// final writer policy; no original payload/path reconstruction is allowed.
    pub(crate) fn current_directory_names(
        target: &Target,
        receipt: &PublicationReceipt,
    ) -> Result<BTreeSet<PathBuf>> {
        revalidate_current_receipt(target, receipt)?;
        Ok(receipt
            .current
            .entries
            .iter()
            .filter(|(p, m)| !p.as_os_str().is_empty() && m.mode & libc::S_IFMT == libc::S_IFDIR)
            .map(|(p, _)| p.clone())
            .collect())
    }
    pub(crate) fn verify_runtime_config_policy(
        target: &Target,
        receipt: &PublicationReceipt,
        policy: &ConfigPolicy,
    ) -> Result<()> {
        revalidate_current_receipt(target, receipt)?;
        if policy
            .leaves
            .values()
            .any(|role| *role == ConfigLeafRole::SystemdDropin)
            && (!policy.root_policy
                || policy.runtime_gid != 0
                || target.path != Path::new(SYSTEMD_DROPIN_TARGET))
        {
            return Err(REFUSED);
        }
        let mode = if policy.root_policy {
            RootMode::RuntimeConfig0700
        } else {
            RootMode::RuntimeConfig0750
        };
        if receipt.intent.root_mode != mode
            || receipt.intent.service_uid != 0
            || receipt.intent.service_gid != policy.runtime_gid
        {
            return Err(REFUSED);
        }
        let mut seen = BTreeSet::new();
        for (path, m) in &receipt.current.entries {
            let attrs = match m.mode & libc::S_IFMT {
                libc::S_IFDIR => (0, policy.runtime_gid, mode.mode()),
                libc::S_IFREG if m.links == 1 => {
                    seen.insert(path.clone());
                    policy.attributes(*policy.leaves.get(path).ok_or(REFUSED)?)
                }
                _ => return Err(REFUSED),
            };
            if (m.uid, m.gid, m.mode & 0o7777) != attrs {
                return Err(REFUSED);
            }
        }
        if seen.iter().ne(policy.leaves.keys()) {
            return Err(REFUSED);
        }
        revalidate_current_receipt(target, receipt)
    }
    pub(crate) fn verify_runtime_state_policy(
        target: &Target,
        receipt: &PublicationReceipt,
        uid: u32,
        gid: u32,
    ) -> Result<()> {
        revalidate_current_receipt(target, receipt)?;
        if receipt.intent.root_mode != RootMode::RuntimeState0700
            || receipt.intent.service_uid != uid
            || receipt.intent.service_gid != gid
        {
            return Err(REFUSED);
        }
        for meta in receipt.current.entries.values() {
            let expected = match meta.mode & libc::S_IFMT {
                libc::S_IFDIR => 0o700,
                libc::S_IFREG if meta.links == 1 => 0o600,
                _ => return Err(REFUSED),
            };
            if meta.uid != uid || meta.gid != gid || meta.mode & 0o7777 != expected {
                return Err(REFUSED);
            }
        }
        revalidate_current_receipt(target, receipt)
    }
    pub(crate) fn revalidate_current_receipt(
        target: &Target,
        receipt: &PublicationReceipt,
    ) -> Result<()> {
        target.revalidate_namespace()?;
        if identity(&stat(receipt.root.as_raw_fd())?) != receipt.intent.new_root {
            return Err(REFUSED);
        }
        if let Some(old) = &receipt.old_root {
            if receipt
                .intent
                .old
                .as_ref()
                .and_then(|g| g.entries.get(Path::new("")))
                .map(|m| &m.id)
                != Some(&identity(&stat(old.as_raw_fd())?))
            {
                return Err(REFUSED);
            }
        }
        if target.path != receipt.intent.target
            || identity(&stat(target.parent.as_raw_fd())?) != receipt.intent.parent
            || target.inspect()?.as_ref() != Some(&receipt.current)
        {
            return Err(REFUSED);
        }
        Ok(())
    }
    // rename changes the directory root ctime, but neither bytes nor child
    // metadata. Permit that one expected syscall effect; no identity relaxation.
    fn same_displaced(actual: Option<&Generation>, expected: Option<&Generation>) -> bool {
        match (actual, expected) {
            (None, None) => true,
            (Some(a), Some(e)) => {
                let mut a = a.clone();
                let Some(root) = a.entries.get_mut(Path::new("")) else {
                    return false;
                };
                let Some(old) = e.entries.get(Path::new("")) else {
                    return false;
                };
                root.ctime = old.ctime;
                root.ctime_ns = old.ctime_ns;
                a == *e
            }
            _ => false,
        }
    }
    fn same_new(
        actual: &Generation,
        expected: &Generation,
        uid: u32,
        gid: u32,
        root_mode: RootMode,
    ) -> bool {
        if root_mode == RootMode::RetainedOriginalTree {
            return same_displaced(Some(actual), Some(expected));
        }
        let mut planned = expected.clone();
        let Some(top) = planned.entries.get_mut(Path::new("")) else {
            return false;
        };
        top.uid = uid;
        top.gid = gid;
        top.mode = (top.mode & libc::S_IFMT) | root_mode.mode();
        same_displaced(Some(actual), Some(&planned))
    }
    fn same_new_or_private(
        actual: &Generation,
        expected: &Generation,
        uid: u32,
        gid: u32,
        root_mode: RootMode,
    ) -> bool {
        // fchown and fchmod are separate atomic syscalls. Admit only the exact
        // intent-defined intermediate new-root owner/group with private0700;
        // child identities/metadata and every other root field stay exact.
        if root_mode == RootMode::RetainedOriginalTree {
            return same_displaced(Some(actual), Some(expected));
        }
        let mut intermediate = expected.clone();
        let Some(top) = intermediate.entries.get_mut(Path::new("")) else {
            return false;
        };
        top.uid = uid;
        top.gid = gid;
        top.mode = (top.mode & !0o777) | 0o700;
        same_new(actual, expected, uid, gid, root_mode)
            || same_displaced(Some(actual), Some(expected))
            || same_displaced(Some(actual), Some(&intermediate))
    }
    /// Receipt-guarded published directory reads. Original source descriptors
    /// are never used to retrieve bytes here. Metadata is checked before/after.
    pub(crate) fn current_leaf_names(
        target: &Target,
        receipt: &PublicationReceipt,
    ) -> Result<BTreeSet<PathBuf>> {
        revalidate_current_receipt(target, receipt)?;
        Ok(receipt
            .current
            .entries
            .iter()
            .filter_map(|(p, m)| {
                if m.mode & libc::S_IFMT == libc::S_IFREG {
                    Some(p.clone())
                } else {
                    None
                }
            })
            .collect())
    }
    pub(crate) fn read_current_leaf(
        target: &Target,
        receipt: &PublicationReceipt,
        path: &Path,
    ) -> Result<Zeroizing<Vec<u8>>> {
        revalidate_current_receipt(target, receipt)?;
        let parts = components(path)?;
        let expected = receipt.current.entries.get(path).ok_or(REFUSED)?;
        if expected.mode & libc::S_IFMT != libc::S_IFREG
            || expected.links != 1
            || expected.size < 0
            || expected.size as usize > MAX_FILE
        {
            return Err(REFUSED);
        }
        let mut parent = dir(receipt.root.as_raw_fd(), &c(OsStr::new("."))?)?;
        let mut prefix = PathBuf::new();
        for name in &parts[..parts.len() - 1] {
            prefix.push(OsStr::from_bytes(name.to_bytes()));
            parent = dir(parent.as_raw_fd(), name)?;
            if receipt.current.entries.get(&prefix) != Some(&metadata(&stat(parent.as_raw_fd())?)) {
                return Err(REFUSED);
            }
        }
        let leaf = parts.last().ok_or(REFUSED)?;
        let f = fd(unsafe {
            libc::openat(
                parent.as_raw_fd(),
                leaf.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        if metadata(&stat(f.as_raw_fd())?) != *expected {
            return Err(REFUSED);
        }
        let mut file = File::from(f);
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(MAX_FILE as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        if bytes.len() > MAX_FILE
            || bytes.len() != expected.size as usize
            || metadata(&stat(file.as_raw_fd())?) != *expected
        {
            return Err(REFUSED);
        }
        revalidate_current_receipt(target, receipt)?;
        Ok(bytes)
    }
    /// Closed original state policy required before publication when exact
    /// retained-tree rollback is requested. Reject rather than normalize.
    pub(crate) fn admit_supported_original_runtime_state(original: &Generation) -> Result<()> {
        if !original.entries.contains_key(Path::new("")) {
            return Err(REFUSED);
        }
        for m in original.entries.values() {
            if !matches!(m.mode & libc::S_IFMT, libc::S_IFDIR | libc::S_IFREG)
                || (m.mode & libc::S_IFMT == libc::S_IFREG && m.links != 1)
                || m.mode & 0o022 != 0
            {
                return Err(REFUSED);
            }
        }
        Ok(())
    }
    /// Exchange the authenticated retained state directory back into place.
    /// No old bytes are recopied and no ownership/permission syscall is used.
    /// Context supplies fresh held stopped-unit admission through `guard`.
    /// The stage namespace/epoch remains the same; the protected receipt chain
    /// must bind this distinct rollback operation and its predecessor hash.
    pub(crate) fn restore_retained_original_tree(
        target: Target,
        current: &PublicationReceipt,
        mut persist: impl FnMut(&PublicationIntent) -> Result<()>,
        guard: &(impl CaptureGuard + ?Sized),
    ) -> Result<PublicationReceipt> {
        revalidate_current_receipt(&target, current)?;
        let eligible = current.intent.root_mode == RootMode::RuntimeState0700
            || (current.intent.root_mode == RootMode::RuntimeConfig0700
                && current.intent.service_uid == 0
                && current.intent.service_gid == 0);
        if !eligible {
            return Err(REFUSED);
        }
        // The additional root/root predecessor is the closed unit-dropin tree:
        // never admit a differently owned/mixed runtime-config publication.
        if current.intent.root_mode == RootMode::RuntimeConfig0700 {
            root_owned_config_tree_exact(&current.current, &current.intent.target)?;
        }
        let old = current.intent.old.as_ref().ok_or(REFUSED)?;
        let original = Generation {
            entries: old.entries.clone(),
        };
        let root_meta = original.entries.get(Path::new("")).ok_or(REFUSED)?;
        admit_supported_original_runtime_state(&original)?;
        let stage = c(OsStr::new(&current.intent.stage))?;
        let retained = dir(target.parent.as_raw_fd(), &stage)?;
        if current
            .old_root
            .as_ref()
            .map(|f| stat(f.as_raw_fd()).map(|s| identity(&s)))
            .transpose()?
            != Some(identity(&stat(retained.as_raw_fd())?))
            || !same_displaced(target.inspect_name(&stage)?.as_ref(), Some(&original))
        {
            return Err(REFUSED);
        }
        // Bind the actual pre-rollback retained generation, after proving it
        // equals the authenticated original except forward-rename root ctime.
        // BeforeRename classification then compares exact current names.
        let retained_generation = target.inspect_name(&stage)?.ok_or(REFUSED)?;
        if !same_displaced(Some(&retained_generation), Some(&original)) {
            return Err(REFUSED);
        }
        let intent = PublicationIntent {
            protocol: current.intent.protocol.clone(),
            epoch: current.intent.epoch.clone(),
            target: target.path.clone(),
            parent: current.intent.parent.clone(),
            stage: current.intent.stage.clone(),
            old: Some(GenerationWire {
                entries: current.current.entries.clone(),
            }),
            new_root: root_meta.id.clone(),
            new_tree: GenerationWire {
                entries: retained_generation.entries.clone(),
            },
            service_uid: root_meta.uid,
            service_gid: root_meta.gid,
            root_mode: RootMode::RetainedOriginalTree,
        };
        validate_intent_shape(&target, &intent)?;
        bind_captured_generation(&target, Some(&current.current), guard)?;
        persist(&intent)?;
        // Recheck both names and the fresh stopped-unit capability after durable
        // intent persistence; a changed generation never authorizes exchange.
        bind_captured_generation(&target, Some(&current.current), guard)?;
        revalidate_current_receipt(&target, current)?;
        if target.inspect_name(&stage)?.as_ref() != Some(&retained_generation) {
            return Err(REFUSED);
        }
        rename(
            target.parent.as_raw_fd(),
            &stage,
            &target.leaf,
            libc::RENAME_EXCHANGE,
        )?;
        sync(target.parent.as_raw_fd())?;
        target.revalidate_namespace()?;
        let restored = target.inspect()?.ok_or(REFUSED)?;
        if !same_displaced(Some(&restored), Some(&original))
            || !same_displaced(
                target.inspect_name(&stage)?.as_ref(),
                Some(&current.current),
            )
        {
            return Err(REFUSED);
        }
        let root = dir(target.parent.as_raw_fd(), &target.leaf)?;
        let displaced = dir(target.parent.as_raw_fd(), &stage)?;
        let receipt = PublicationReceipt {
            intent,
            current: restored,
            root,
            old_root: Some(displaced),
        };
        revalidate_current_receipt(&target, &receipt)?;
        Ok(receipt)
    }
    /// Scan the held inode tree against its recorded original generation. Only
    /// the root ctime effect of rename is tolerated; child identities, complete
    /// membership, modes, owners, size and timestamps remain exact. Generation
    /// stores metadata, not a new historical byte digest: protected Context
    /// admission and original capture supply that separate provenance.
    fn revalidate_predecessor_tree(root: &OwnedFd, expected: &Generation) -> Result<()> {
        let mut entries = BTreeMap::new();
        let mut total = 0;
        scan(root.as_raw_fd(), Path::new(""), 0, &mut entries, &mut total)?;
        if !same_displaced(Some(&Generation { entries }), Some(expected)) {
            return Err(REFUSED);
        }
        Ok(())
    }
    /// Bind an actual retained-original rollback to its actual forward receipt.
    /// Neither the enum nor a caller-provided digest is predecessor authority.
    /// Context must separately authenticate this pair's protected role/journal.
    pub(crate) fn validate_retained_restore_predecessor(
        forward: &PublicationReceipt,
        restored: &PublicationReceipt,
    ) -> Result<()> {
        let target = Target::open(&restored.intent.target)?;
        validate_intent_shape(&target, &forward.intent)?;
        validate_intent_shape(&target, &restored.intent)?;
        revalidate_current_receipt(&target, restored)?;
        let eligible = forward.intent.root_mode == RootMode::RuntimeState0700
            || (forward.intent.root_mode == RootMode::RuntimeConfig0700
                && forward.intent.service_uid == 0
                && forward.intent.service_gid == 0);
        if !eligible
            || restored.intent.root_mode != RootMode::RetainedOriginalTree
            || restored.intent.protocol != forward.intent.protocol
            || restored.intent.target != forward.intent.target
            || restored.intent.parent != forward.intent.parent
            || restored.intent.epoch != forward.intent.epoch
            || restored.intent.stage != forward.intent.stage
            || forward.current.root_identity()? != forward.intent.new_root
        {
            return Err(REFUSED);
        }
        // Mirror the closed root/root Unit predecessor admitted by the
        // actual restoration constructor; mixed runtime config is not Unit.
        if forward.intent.root_mode == RootMode::RuntimeConfig0700 {
            root_owned_config_tree_exact(&forward.current, &forward.intent.target)?;
        }
        let original = Generation {
            entries: forward.intent.old.as_ref().ok_or(REFUSED)?.entries.clone(),
        };
        let retired = Generation {
            entries: restored.intent.old.as_ref().ok_or(REFUSED)?.entries.clone(),
        };
        let planned = Generation {
            entries: restored.intent.new_tree.entries.clone(),
        };
        if retired != forward.current
            || !same_displaced(Some(&planned), Some(&original))
            || !same_displaced(Some(&restored.current), Some(&original))
            || restored.intent.new_root != original.root_identity()?
        {
            return Err(REFUSED);
        }
        let held_original = forward.old_root.as_ref().ok_or(REFUSED)?;
        let held_retired = restored.old_root.as_ref().ok_or(REFUSED)?;
        if identity(&stat(held_original.as_raw_fd())?) != restored.intent.new_root
            || identity(&stat(restored.root.as_raw_fd())?) != original.root_identity()?
            || identity(&stat(held_retired.as_raw_fd())?) != forward.intent.new_root
            || identity(&stat(forward.root.as_raw_fd())?) != forward.intent.new_root
        {
            return Err(REFUSED);
        }
        let stage = c(OsStr::new(&restored.intent.stage))?;
        if !same_displaced(
            target.inspect_name(&stage)?.as_ref(),
            Some(&forward.current),
        ) {
            return Err(REFUSED);
        }
        revalidate_predecessor_tree(held_original, &original)?;
        revalidate_predecessor_tree(&restored.root, &original)?;
        revalidate_predecessor_tree(&forward.root, &forward.current)?;
        revalidate_predecessor_tree(held_retired, &forward.current)?;
        revalidate_current_receipt(&target, restored)
    }
    /// Match actual withdrawal/retirement to its forward inode and epoch.
    /// Do not require direct old=None: an authenticated earlier original-absence
    /// chain may legitimately contain intervening owned publications. Context's
    /// original-absence authority remains required by the mutation API.
    pub(crate) fn validate_withdrawal_predecessor(
        forward: &PublicationReceipt,
        withdrawn: &WithdrawalReceipt,
    ) -> Result<()> {
        let target = Target::open(&withdrawn.intent.target)?;
        validate_intent_shape(&target, &forward.intent)?;
        if withdrawn.intent.protocol != "auto-config-withdrawal-v1"
            || withdrawn.intent.target != forward.intent.target
            || withdrawn.intent.parent != forward.intent.parent
            || !withdrawn.intent.retired_name.starts_with(".auto-config-")
            || withdrawn.intent.retired_name.len() != 45
            || !withdrawn.intent.retired_name[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || withdrawn.intent.publication_epoch != forward.intent.epoch
            || withdrawn.intent.current.entries != forward.current.entries
            || withdrawn.intent.root != forward.intent.new_root
            || forward.current.root_identity()? != forward.intent.new_root
            || !same_displaced(Some(&withdrawn.retired), Some(&forward.current))
        {
            return Err(REFUSED);
        }
        withdrawn.revalidate_held_retired()?;
        revalidate_withdrawal(&target, withdrawn)?;
        revalidate_predecessor_tree(&forward.root, &forward.current)?;
        revalidate_predecessor_tree(&withdrawn.root, &forward.current)?;
        revalidate_withdrawal(&target, withdrawn)
    }
    /// Read the exact fixed durable leaf again through the held admitted stage.
    /// Historical metadata is never a live target/retirement observation.
    fn recheck_historical_withdrawal_pair_record(record: &AuthenticatedRecord) -> Result<()> {
        record.recheck_stage()?;
        let leaf = match &record.record {
            DurableRecord::Publication { .. } => "publication-receipt.json",
            DurableRecord::Withdrawal { .. } => "withdrawal-receipt.json",
            _ => return Err(REFUSED),
        };
        let binding = record.record.binding();
        if !valid_binding(binding) || binding.transaction_stage != record.stage_id {
            return Err(REFUSED);
        }
        let name = c(OsStr::new(leaf))?;
        let held = fd(unsafe {
            libc::openat(
                record.stage.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        })?;
        let before = stat(held.as_raw_fd())?;
        if before.st_mode != (libc::S_IFREG | 0o600)
            || before.st_uid != unsafe { libc::geteuid() }
            || before.st_nlink != 1
            || before.st_size < 0
            || before.st_size > 4 * 1024 * 1024
        {
            return Err(REFUSED);
        }
        let mut file = File::from(held);
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        if bytes.len() > 4 * 1024 * 1024
            || metadata(&stat(file.as_raw_fd())?) != metadata(&before)
            || format!("{:x}", Sha256::digest(bytes.as_slice())) != record.hash
        {
            return Err(REFUSED);
        }
        let named = fd(unsafe {
            libc::openat(
                record.stage.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        })?;
        if metadata(&stat(named.as_raw_fd())?) != metadata(&before) {
            return Err(REFUSED);
        }
        record.recheck_stage()
    }
    /// Historical protected pair linkage only. Store PhaseAuthority must have
    /// admitted each exact role/phase/predecessor claim; original-kind2 and the
    /// complete owned chain are re-admitted through the mandatory authority.
    /// The old publication target may no longer exist, so never reopen it here.
    /// Live absence and the held retired tree require a separate actual reopen.
    pub(crate) fn validate_authenticated_withdrawal_predecessor(
        forward: &AuthenticatedRecord,
        withdrawn: &AuthenticatedRecord,
        absence: &(impl OwnAbsenceChainAuthority + ?Sized),
    ) -> Result<()> {
        recheck_historical_withdrawal_pair_record(forward)?;
        recheck_historical_withdrawal_pair_record(withdrawn)?;
        let DurableRecord::Publication {
            binding: first,
            intent: publication,
            current,
        } = &forward.record
        else {
            return Err(REFUSED);
        };
        let DurableRecord::Withdrawal {
            binding: last,
            intent: withdrawal,
            retired,
        } = &withdrawn.record
        else {
            return Err(REFUSED);
        };
        absence.validate_original_absence_and_chain(&publication.target, &publication.epoch)?;
        let expected = Generation {
            entries: current.entries.clone(),
        };
        let actual = Generation {
            entries: retired.entries.clone(),
        };
        if first.transaction_nonce != last.transaction_nonce
            || last.phase != "rollback"
            || publication.protocol != "auto-config-publication-v1"
            || publication.epoch != publication.stage
            || !publication.epoch.starts_with(".auto-config-")
            || publication.epoch.len() != 45
            || !publication.epoch[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || withdrawal.protocol != "auto-config-withdrawal-v1"
            || withdrawal.target != publication.target
            || withdrawal.parent != publication.parent
            || withdrawal.publication_epoch != publication.epoch
            || withdrawal.root != publication.new_root
            || expected.root_identity()? != publication.new_root
            || withdrawal.current.entries != current.entries
            || !withdrawal.retired_name.starts_with(".auto-config-")
            || withdrawal.retired_name.len() != 45
            || !withdrawal.retired_name[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !same_displaced(Some(&actual), Some(&expected))
        {
            return Err(REFUSED);
        }
        recheck_historical_withdrawal_pair_record(forward)?;
        recheck_historical_withdrawal_pair_record(withdrawn)?;
        absence.validate_original_absence_and_chain(&publication.target, &publication.epoch)
    }
    /// Restore immutable captured old bytes only after the current own receipt
    /// still matches. Original backup is never trusted as a source or deleted.
    pub(crate) fn restore_captured(
        target: Target,
        current: &PublicationReceipt,
        old: &CapturedTree,
        uid: u32,
        gid: u32,
        preserve_stage: impl FnMut(&StageReceipt) -> Result<()>,
        persist: impl FnMut(&PublicationIntent) -> Result<()>,
    ) -> Result<PublicationReceipt> {
        revalidate_current_receipt(&target, current)?;
        Prepared::build_policy(
            target,
            Some(current.current.clone()),
            old,
            uid,
            gid,
            current.intent.root_mode,
            preserve_stage,
        )?
        .publish(persist, |t, _| revalidate_current_receipt(t, current))
    }
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct RecordBinding {
        pub transaction_stage: Identity,
        pub transaction_nonce: String,
        pub phase: String,
        pub chain_sha256: String,
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum DurableRecord {
        Publication {
            binding: RecordBinding,
            intent: PublicationIntent,
            current: GenerationWire,
        },
        Withdrawal {
            binding: RecordBinding,
            intent: WithdrawalIntent,
            retired: GenerationWire,
        },
        Projection {
            binding: RecordBinding,
            base_record_sha256: String,
            intent: PublicationIntent,
            base_current: GenerationWire,
            accepted: GenerationWire,
            main_sha256: String,
        },
    }
    impl DurableRecord {
        fn binding(&self) -> &RecordBinding {
            match self {
                Self::Publication { binding, .. }
                | Self::Withdrawal { binding, .. }
                | Self::Projection { binding, .. } => binding,
            }
        }
    }
    fn valid_binding(b: &RecordBinding) -> bool {
        !b.phase.is_empty()
            && b.phase.len() <= 64
            && b.phase.bytes().all(|x| x.is_ascii_lowercase() || x == b'_')
            && b.transaction_nonce.len() == 32
            && b.transaction_nonce
                .bytes()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
            && b.chain_sha256.len() == 64
            && b.chain_sha256
                .bytes()
                .all(|x| x.is_ascii_digit() || (b'a'..=b'f').contains(&x))
    }
    impl PublicationReceipt {
        /// Serialize the ACTUAL descriptor-minted receipt, with Store binding.
        /// Store must persist under admitted root-stage and sync before advancing.
        pub fn durable_bytes(&self, binding: RecordBinding) -> Result<Vec<u8>> {
            if !valid_binding(&binding) {
                return Err(REFUSED);
            }
            serde_json::to_vec(&DurableRecord::Publication {
                binding,
                intent: self.intent.clone(),
                current: GenerationWire {
                    entries: self.current.entries.clone(),
                },
            })
            .map_err(|_| REFUSED)
        }
    }
    pub(crate) struct RecordClaim {
        pub actual_stage: Identity,
        pub administrator_uid: u32,
        pub record_leaf: String,
        pub record_sha256: String,
        pub binding: RecordBinding,
    }
    /// Store implementation MUST bind claim to protected original transaction
    /// stage identity/nonce, current phase, durable hash chain, record hash and
    /// operation kind. This module intentionally supplies no implementation.
    pub(crate) trait PhaseAuthority {
        fn validate_record_claim(&self, claim: &RecordClaim) -> Result<()>;
    }
    /// Cannot be constructed from JSON: owns admitted root-stage FD and stores
    /// bytes read through that FD plus a positively checked typed Store claim.
    pub(crate) struct AuthenticatedRecord {
        stage: OwnedFd,
        stage_id: Identity,
        record: DurableRecord,
        hash: String,
    }
    pub(crate) fn authenticate_record(
        stage: OwnedFd,
        leaf: &str,
        authority: &(impl PhaseAuthority + ?Sized),
    ) -> Result<AuthenticatedRecord> {
        if !matches!(
            leaf,
            "publication-receipt.json" | "withdrawal-receipt.json" | "projection-receipt.json"
        ) {
            return Err(REFUSED);
        }
        let admin = unsafe { libc::geteuid() };
        let ss = stat(stage.as_raw_fd())?;
        if ss.st_mode & libc::S_IFMT != libc::S_IFDIR
            || ss.st_uid != admin
            || ss.st_mode & 0o777 != 0o700
        {
            return Err(REFUSED);
        }
        let name = c(OsStr::new(leaf))?;
        let f = fd(unsafe {
            libc::openat(
                stage.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        })?;
        let fs = stat(f.as_raw_fd())?;
        if fs.st_mode & libc::S_IFMT != libc::S_IFREG
            || fs.st_uid != admin
            || fs.st_mode & 0o777 != 0o600
            || fs.st_nlink != 1
            || fs.st_size < 0
            || fs.st_size > 4 * 1024 * 1024
        {
            return Err(REFUSED);
        }
        let mut bytes = Zeroizing::new(Vec::new());
        let mut file = File::from(f);
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        if bytes.len() > 4 * 1024 * 1024 || metadata(&stat(file.as_raw_fd())?) != metadata(&fs) {
            return Err(REFUSED);
        }
        let record: DurableRecord = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        if !valid_binding(record.binding()) || record.binding().transaction_stage != identity(&ss) {
            return Err(REFUSED);
        }
        if !matches!(
            (&record, leaf),
            (
                DurableRecord::Publication { .. },
                "publication-receipt.json"
            ) | (DurableRecord::Withdrawal { .. }, "withdrawal-receipt.json")
                | (DurableRecord::Projection { .. }, "projection-receipt.json")
        ) {
            return Err(REFUSED);
        }
        let hash = format!("{:x}", Sha256::digest(bytes.as_slice()));
        authority.validate_record_claim(&RecordClaim {
            actual_stage: identity(&ss),
            administrator_uid: admin,
            record_leaf: leaf.into(),
            record_sha256: hash.clone(),
            binding: record.binding().clone(),
        })?;
        Ok(AuthenticatedRecord {
            stage,
            stage_id: identity(&ss),
            record,
            hash,
        })
    }
    impl AuthenticatedRecord {
        /// Active runtime state may gain files after publication. Bind its
        /// original protected publication record to the live root directory
        /// without treating mutable descendants as immutable config bytes.
        /// A typed Main/Stop proof is still required by the caller.
        pub fn live_mutable_root_binding_sha256(&self, target: &Target) -> Result<String> {
            self.recheck_stage()?;
            let (intent, generation) = match &self.record {
                DurableRecord::Publication {
                    intent, current, ..
                } => (intent, current),
                DurableRecord::Projection {
                    intent, accepted, ..
                } => (intent, accepted),
                DurableRecord::Withdrawal { .. } => return Err(REFUSED),
            };
            validate_intent_shape(target, intent)?;
            target.revalidate_namespace()?;
            let opened = dir(target.parent.as_raw_fd(), &target.leaf)?;
            let actual = stat(opened.as_raw_fd())?;
            let expected = generation.entries.get(Path::new("")).ok_or(REFUSED)?;
            if actual.st_mode & libc::S_IFMT != libc::S_IFDIR
                || identity(&actual) != intent.new_root
                || expected.id != intent.new_root
                || actual.st_uid != expected.uid
                || actual.st_gid != expected.gid
                || actual.st_mode != expected.mode
            {
                return Err(REFUSED);
            }
            self.recheck_stage()?;
            target.revalidate_namespace()?;
            let named = dir(target.parent.as_raw_fd(), &target.leaf)?;
            if identity(&stat(named.as_raw_fd())?) != identity(&actual)
                || identity(&stat(opened.as_raw_fd())?) != identity(&actual)
            {
                return Err(REFUSED);
            }
            let source = serde_json::to_vec(&(
                "aegis-auto-live-state-root-v1",
                self.record_hash(),
                &intent.new_root,
                actual.st_uid,
                actual.st_gid,
                actual.st_mode,
            ))
            .map_err(|_| REFUSED)?;
            Ok(format!("{:x}", Sha256::digest(source)))
        }
        /// Historical semantics of a positively admitted protected Publication record.
        /// This does not reopen the now-restored target or prove its current state.
        /// The digest matches the owned-unit namespace domain; live restoration,
        /// captured bytes and authenticated rollback-journal admission stay separate.
        pub fn publication_semantics_sha256(&self) -> Result<String> {
            self.recheck_publication_record()?;
            let DurableRecord::Publication {
                intent, current, ..
            } = &self.record
            else {
                return Err(REFUSED);
            };
            let mut semantics = b"aegis-owned-unit-dropin-receipt-v1\0".to_vec();
            semantics.extend_from_slice(&serde_json::to_vec(intent).map_err(|_| REFUSED)?);
            semantics.extend_from_slice(
                &Generation {
                    entries: current.entries.clone(),
                }
                .witness()?,
            );
            self.recheck_publication_record()?;
            Ok(format!("{:x}", Sha256::digest(&semantics)))
        }
        /// Original metadata from the positively admitted historical Publication
        /// intent. This neither opens the current target nor grants publication or
        /// rollback authority; Context and live retained/absence checks stay required.
        pub fn original_generation(&self) -> Result<Option<Generation>> {
            self.recheck_publication_record()?;
            let DurableRecord::Publication { intent, .. } = &self.record else {
                return Err(REFUSED);
            };
            let original = intent.old.as_ref().map(|old| Generation {
                entries: old.entries.clone(),
            });
            self.recheck_publication_record()?;
            Ok(original)
        }
        fn recheck_publication_record(&self) -> Result<()> {
            self.recheck_stage()?;
            if !matches!(&self.record, DurableRecord::Publication { .. }) {
                return Err(REFUSED);
            }
            // Revalidate exact protected record bytes through the owned stage FD.
            // No caller JSON, path, digest or publication-role override is accepted.
            let name = c(OsStr::new("publication-receipt.json"))?;
            let opened = fd(unsafe {
                libc::openat(
                    self.stage.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            })?;
            let before = stat(opened.as_raw_fd())?;
            if before.st_mode & libc::S_IFMT != libc::S_IFREG
                || before.st_uid != unsafe { libc::geteuid() }
                || before.st_mode & 0o777 != 0o600
                || before.st_nlink != 1
                || before.st_size < 0
                || before.st_size > 4 * 1024 * 1024
            {
                return Err(REFUSED);
            }
            let mut bytes = Zeroizing::new(Vec::new());
            let mut file = File::from(opened);
            (&mut file)
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| REFUSED)?;
            if bytes.len() > 4 * 1024 * 1024
                || metadata(&stat(file.as_raw_fd())?) != metadata(&before)
                || format!("{:x}", Sha256::digest(bytes.as_slice())) != self.hash
            {
                return Err(REFUSED);
            }
            self.recheck_stage()?;
            Ok(())
        }
        pub fn record_hash(&self) -> &str {
            &self.hash
        }
        fn recheck_stage(&self) -> Result<()> {
            let s = stat(self.stage.as_raw_fd())?;
            if identity(&s) != self.stage_id
                || s.st_uid != unsafe { libc::geteuid() }
                || s.st_mode & 0o777 != 0o700
            {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
    /// Historical retained-restoration linkage from two positively admitted
    /// private Publication records. Never a current-target or rollback authority:
    /// Context journal authentication and live restored/retired FD checks remain.
    pub(crate) fn validate_authenticated_retained_restore_predecessor(
        forward: &AuthenticatedRecord,
        restored: &AuthenticatedRecord,
    ) -> Result<()> {
        forward.recheck_publication_record()?;
        restored.recheck_publication_record()?;
        let DurableRecord::Publication {
            intent: f,
            current: fc,
            ..
        } = &forward.record
        else {
            return Err(REFUSED);
        };
        let DurableRecord::Publication {
            intent: r,
            current: rc,
            ..
        } = &restored.record
        else {
            return Err(REFUSED);
        };
        for intent in [f, r] {
            if intent.protocol != "auto-config-publication-v1"
                || !intent.target.is_absolute()
                || intent.target == Path::new("/")
                || intent.target.components().any(|component| {
                    !matches!(
                        component,
                        std::path::Component::RootDir | std::path::Component::Normal(_)
                    )
                })
                || intent.epoch != intent.stage
                || !intent.stage.starts_with(".auto-config-")
                || intent.stage.len() != 45
                || !intent.stage[13..]
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return Err(REFUSED);
            }
        }
        let eligible = f.root_mode == RootMode::RuntimeState0700
            || (f.root_mode == RootMode::RuntimeConfig0700
                && f.service_uid == 0
                && f.service_gid == 0);
        let current = Generation {
            entries: fc.entries.clone(),
        };
        let restored_current = Generation {
            entries: rc.entries.clone(),
        };
        let original = Generation {
            entries: f.old.as_ref().ok_or(REFUSED)?.entries.clone(),
        };
        let retired = Generation {
            entries: r.old.as_ref().ok_or(REFUSED)?.entries.clone(),
        };
        let planned = Generation {
            entries: r.new_tree.entries.clone(),
        };
        let original_root = original.entries.get(Path::new("")).ok_or(REFUSED)?;
        admit_supported_original_runtime_state(&original)?;
        if !eligible
            || r.root_mode != RootMode::RetainedOriginalTree
            || r.target != f.target
            || r.parent != f.parent
            || r.epoch != f.epoch
            || r.stage != f.stage
            || current.root_identity()? != f.new_root
            || r.new_root != original_root.id
            || r.service_uid != original_root.uid
            || r.service_gid != original_root.gid
            || retired != current
            || !same_displaced(Some(&planned), Some(&original))
            || !same_displaced(Some(&restored_current), Some(&original))
        {
            return Err(REFUSED);
        }
        if f.root_mode == RootMode::RuntimeConfig0700 {
            root_owned_config_tree_exact(&current, &f.target)?;
        }
        forward.recheck_publication_record()?;
        restored.recheck_publication_record()?;
        Ok(())
    }
    /// Exact owned-unit retained-restoration semantic domain from authenticated
    /// historical records. Does not replace live inode/attrs/bytes readback or
    /// protected Context rollback admission.
    pub(crate) fn authenticated_unit_retained_restoration_semantics_sha256(
        forward: &AuthenticatedRecord,
        restored: &AuthenticatedRecord,
    ) -> Result<String> {
        validate_authenticated_retained_restore_predecessor(forward, restored)?;
        let DurableRecord::Publication {
            intent, current, ..
        } = &restored.record
        else {
            return Err(REFUSED);
        };
        let mut bytes = b"aegis-owned-unit-dropin-restoration-v1\0".to_vec();
        bytes.extend_from_slice(forward.publication_semantics_sha256()?.as_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&serde_json::to_vec(intent).map_err(|_| REFUSED)?);
        bytes.extend_from_slice(
            &Generation {
                entries: current.entries.clone(),
            }
            .witness()?,
        );
        validate_authenticated_retained_restore_predecessor(forward, restored)?;
        Ok(format!("{:x}", Sha256::digest(&bytes)))
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct IntentRecord {
        schema: String,
        binding: RecordBinding,
        intent: PublicationIntent,
    }
    impl PublicationIntent {
        pub(crate) fn epoch(&self) -> &str {
            &self.epoch
        }
        /// Called only on the descriptor-minted intent before rename. Store
        /// writes/syncs this closed pending record and pins its exact hash/phase.
        pub fn durable_bytes(&self, binding: RecordBinding) -> Result<Vec<u8>> {
            if !valid_binding(&binding) {
                return Err(REFUSED);
            }
            serde_json::to_vec(&IntentRecord {
                schema: "auto-config-publication-intent-v1".into(),
                binding,
                intent: self.clone(),
            })
            .map_err(|_| REFUSED)
        }
    }
    /// No JSON constructor. Owns admitted private transaction-stage descriptor
    /// and required positively validated Store pending-phase/hash-chain claim.
    pub(crate) struct AuthenticatedIntent {
        stage: OwnedFd,
        stage_id: Identity,
        record: IntentRecord,
        hash: String,
    }
    impl AuthenticatedIntent {
        pub fn record_hash(&self) -> &str {
            &self.hash
        }
        fn recheck_stage(&self) -> Result<()> {
            let s = stat(self.stage.as_raw_fd())?;
            if identity(&s) != self.stage_id
                || s.st_uid != unsafe { libc::geteuid() }
                || s.st_mode & 0o777 != 0o700
            {
                return Err(REFUSED);
            }
            // Revalidate the actual immutable protected pending intent bytes,
            // not merely its stage directory. Selected original input paths are
            // never read here. Preserve exact PhaseAuthority-pinned raw hash.
            let leaf = c(OsStr::new("publication-intent.json"))?;
            let held = fd(unsafe {
                libc::openat(
                    self.stage.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            })?;
            let before = stat(held.as_raw_fd())?;
            if before.st_mode != (libc::S_IFREG | 0o600)
                || before.st_uid != s.st_uid
                || before.st_nlink != 1
                || before.st_size < 0
                || before.st_size > 4 * 1024 * 1024
            {
                return Err(REFUSED);
            }
            let mut file = File::from(held);
            let mut bytes = Zeroizing::new(Vec::new());
            (&mut file)
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| REFUSED)?;
            if bytes.len() > 4 * 1024 * 1024
                || metadata(&stat(file.as_raw_fd())?) != metadata(&before)
                || format!("{:x}", Sha256::digest(bytes.as_slice())) != self.record_hash()
            {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
    pub(crate) fn authenticate_intent(
        stage: OwnedFd,
        authority: &(impl PhaseAuthority + ?Sized),
    ) -> Result<AuthenticatedIntent> {
        let admin = unsafe { libc::geteuid() };
        let ss = stat(stage.as_raw_fd())?;
        if ss.st_mode & libc::S_IFMT != libc::S_IFDIR
            || ss.st_uid != admin
            || ss.st_mode & 0o777 != 0o700
        {
            return Err(REFUSED);
        }
        let name = c(OsStr::new("publication-intent.json"))?;
        let fd = fd(unsafe {
            libc::openat(
                stage.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        })?;
        let fs = stat(fd.as_raw_fd())?;
        if fs.st_mode & libc::S_IFMT != libc::S_IFREG
            || fs.st_uid != admin
            || fs.st_mode & 0o777 != 0o600
            || fs.st_nlink != 1
            || fs.st_size < 0
            || fs.st_size > 4 * 1024 * 1024
        {
            return Err(REFUSED);
        }
        let mut file = File::from(fd);
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        if bytes.len() > 4 * 1024 * 1024 || metadata(&stat(file.as_raw_fd())?) != metadata(&fs) {
            return Err(REFUSED);
        }
        let record: IntentRecord = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        if record.schema != "auto-config-publication-intent-v1"
            || !valid_binding(&record.binding)
            || record.binding.transaction_stage != identity(&ss)
        {
            return Err(REFUSED);
        }
        let hash = format!("{:x}", Sha256::digest(bytes.as_slice()));
        // Store must require Header.pending: exact current role, phase, stage
        // identity/nonce and this hash. No default authority implementation.
        authority.validate_record_claim(&RecordClaim {
            actual_stage: identity(&ss),
            administrator_uid: admin,
            record_leaf: "publication-intent.json".into(),
            record_sha256: hash.clone(),
            binding: record.binding.clone(),
        })?;
        Ok(AuthenticatedIntent {
            stage,
            stage_id: identity(&ss),
            record,
            hash,
        })
    }
    /// Reconcile the actual interrupted rename, never interpret a phase alone
    /// as absence of publication. None means no rename and retains new stage.
    /// After rename, validate exact OWN topology and complete only new-root FD
    /// metadata if interruption left it administrator0700; originals untouched.
    pub(crate) fn recover_own_receipt(
        target: &Target,
        pending: &AuthenticatedIntent,
    ) -> Result<Option<PublicationReceipt>> {
        pending.recheck_stage()?;
        let intent = &pending.record.intent;
        match classify_interrupted(target, intent)? {
            InterruptedState::BeforeRename => Ok(None),
            InterruptedState::PublishedNeedsAcceptance => {
                let current = target.inspect()?.ok_or(REFUSED)?;
                let planned = Generation {
                    entries: intent.new_tree.entries.clone(),
                };
                if !same_new_or_private(
                    &current,
                    &planned,
                    intent.service_uid,
                    intent.service_gid,
                    intent.root_mode,
                ) {
                    return Err(REFUSED);
                }
                let root = dir(target.parent.as_raw_fd(), &target.leaf)?;
                if identity(&stat(root.as_raw_fd())?) != intent.new_root {
                    return Err(REFUSED);
                }
                let old_root = if let Some(old) = &intent.old {
                    let name = c(OsStr::new(&intent.stage))?;
                    let expected = Generation {
                        entries: old.entries.clone(),
                    };
                    if !same_displaced(target.inspect_name(&name)?.as_ref(), Some(&expected)) {
                        return Err(REFUSED);
                    }
                    let old_fd = dir(target.parent.as_raw_fd(), &name)?;
                    if identity(&stat(old_fd.as_raw_fd())?) != expected.root_identity()? {
                        return Err(REFUSED);
                    }
                    Some(old_fd)
                } else {
                    None
                };
                // Last namespace/current recheck before new-only root metadata.
                target.revalidate_namespace()?;
                if target.inspect()?.as_ref() != Some(&current) {
                    return Err(REFUSED);
                }
                if !same_new(
                    &current,
                    &planned,
                    intent.service_uid,
                    intent.service_gid,
                    intent.root_mode,
                ) {
                    // Retained originals are never permission-repaired, even
                    // if future intermediate matching changes. Refuse instead.
                    if intent.root_mode == RootMode::RetainedOriginalTree {
                        return Err(REFUSED);
                    }
                    let rs = stat(root.as_raw_fd())?;
                    if rs.st_mode & 0o777 != 0o700
                        || !((rs.st_uid == target.admin)
                            || (rs.st_uid == intent.service_uid && rs.st_gid == intent.service_gid))
                    {
                        return Err(REFUSED);
                    }
                    set_new(
                        root.as_raw_fd(),
                        intent.service_uid,
                        intent.service_gid,
                        intent.root_mode.mode(),
                    )?;
                    sync(root.as_raw_fd())?;
                }
                let actual = target.inspect()?.ok_or(REFUSED)?;
                if !same_new(
                    &actual,
                    &planned,
                    intent.service_uid,
                    intent.service_gid,
                    intent.root_mode,
                ) {
                    return Err(REFUSED);
                }
                sync(target.parent.as_raw_fd())?;
                let receipt = PublicationReceipt {
                    intent: intent.clone(),
                    current: actual,
                    root,
                    old_root,
                };
                revalidate_current_receipt(target, &receipt)?;
                Ok(Some(receipt))
            }
        }
    }
    pub(crate) struct ProjectionSource {
        target: PathBuf,
        base_record_sha256: String,
        epoch: String,
        root: Identity,
    }
    impl ProjectionSource {
        pub fn target(&self) -> &Path {
            &self.target
        }
        pub fn base_record_sha256(&self) -> &str {
            &self.base_record_sha256
        }
        pub fn epoch(&self) -> &str {
            &self.epoch
        }
        pub fn root(&self) -> &Identity {
            &self.root
        }
    }
    /// Actual protected Store must bind accepted RenderContext/main leaf,
    /// Metadata phase/capture lifecycle, selected mode and exact ACTIVE base
    /// record hash/epoch/root identity. This module supplies no implementation.
    pub(crate) trait ProjectionAdmission {
        fn admit_projection_source(&self, source: &ProjectionSource) -> Result<()>;
    }
    fn projected_generation(
        actual: &Generation,
        base: &Generation,
        intent: &PublicationIntent,
    ) -> Result<()> {
        if !matches!(
            intent.root_mode,
            RootMode::ServiceConfig0750 | RootMode::RuntimeConfig0700 | RootMode::RuntimeConfig0750
        ) || actual.entries.keys().ne(base.entries.keys())
        {
            return Err(REFUSED);
        }
        let mut normalized = actual.clone();
        let top = normalized.entries.get_mut(Path::new("")).ok_or(REFUSED)?;
        let old_top = base.entries.get(Path::new("")).ok_or(REFUSED)?;
        top.mtime = old_top.mtime;
        top.mtime_ns = old_top.mtime_ns;
        top.ctime = old_top.ctime;
        top.ctime_ns = old_top.ctime_ns;
        if top != old_top {
            return Err(REFUSED);
        }
        let actual_main = normalized
            .entries
            .get(Path::new("aegis.toml"))
            .ok_or(REFUSED)?;
        let base_main = base.entries.get(Path::new("aegis.toml")).ok_or(REFUSED)?;
        if actual_main.mode != base_main.mode
            || actual_main.mode & libc::S_IFMT != libc::S_IFREG
            || actual_main.links != 1
            || actual_main.uid != base_main.uid
            || actual_main.gid != base_main.gid
            || actual_main.size <= 0
            || actual_main.size > 4 * 1024 * 1024
        {
            return Err(REFUSED);
        }
        normalized.entries.insert(
            PathBuf::from("aegis.toml"),
            base.entries
                .get(Path::new("aegis.toml"))
                .ok_or(REFUSED)?
                .clone(),
        );
        if normalized != *base {
            return Err(REFUSED);
        }
        Ok(())
    }
    #[derive(Clone, Debug, Serialize)]
    pub(crate) struct ProjectionIntent {
        schema: String,
        base_record_sha256: String,
        intent: PublicationIntent,
        base_current: GenerationWire,
        accepted: GenerationWire,
        main_sha256: String,
    }
    impl ProjectionIntent {
        pub fn durable_bytes(&self, binding: RecordBinding) -> Result<Vec<u8>> {
            if !valid_binding(&binding) || binding.phase != "projection" {
                return Err(REFUSED);
            }
            serde_json::to_vec(&serde_json::json!({"schema":"auto-config-projection-intent-v1","binding":binding,"projection":self})).map_err(|_|REFUSED)
        }
    }
    /// Metadata-provisional view: only admitted main formatting may differ.
    /// Own retained root/backup identities and immutable current metadata anchor
    /// all reads until actual whole-renderer semantic validation succeeds.
    pub(crate) struct ProjectionView {
        source: ProjectionSource,
        receipt: PublicationReceipt,
        main: Zeroizing<Vec<u8>>,
        main_sha256: String,
        base_current: Generation,
    }
    impl ProjectionView {
        pub fn admit(
            target: &Target,
            record: &AuthenticatedRecord,
            authority: &(impl ProjectionAdmission + ?Sized),
        ) -> Result<Self> {
            record.recheck_stage()?;
            let (intent, base) = match &record.record {
                DurableRecord::Publication {
                    intent, current, ..
                } => (
                    intent.clone(),
                    Generation {
                        entries: current.entries.clone(),
                    },
                ),
                DurableRecord::Projection {
                    intent, accepted, ..
                } => (
                    intent.clone(),
                    Generation {
                        entries: accepted.entries.clone(),
                    },
                ),
                _ => return Err(REFUSED),
            };
            validate_intent_shape(target, &intent)?;
            let source = ProjectionSource {
                target: target.path.clone(),
                base_record_sha256: record.record_hash().to_string(),
                epoch: intent.epoch.clone(),
                root: intent.new_root.clone(),
            };
            authority.admit_projection_source(&source)?;
            let actual = target.inspect()?.ok_or(REFUSED)?;
            projected_generation(&actual, &base, &intent)?;
            let root = dir(target.parent.as_raw_fd(), &target.leaf)?;
            if identity(&stat(root.as_raw_fd())?) != intent.new_root {
                return Err(REFUSED);
            }
            let old_root = if let Some(old) = &intent.old {
                let name = c(OsStr::new(&intent.stage))?;
                if !same_displaced(
                    target.inspect_name(&name)?.as_ref(),
                    Some(&Generation {
                        entries: old.entries.clone(),
                    }),
                ) {
                    return Err(REFUSED);
                }
                Some(dir(target.parent.as_raw_fd(), &name)?)
            } else {
                None
            };
            let receipt = PublicationReceipt {
                intent,
                current: actual,
                root,
                old_root,
            };
            let main = read_current_leaf(target, &receipt, Path::new("aegis.toml"))?;
            let main_sha256 = format!("{:x}", Sha256::digest(main.as_slice()));
            authority.admit_projection_source(&source)?;
            revalidate_current_receipt(target, &receipt)?;
            Ok(Self {
                source,
                receipt,
                main,
                main_sha256,
                base_current: base,
            })
        }
        pub fn source(&self) -> &ProjectionSource {
            &self.source
        }
        pub fn main_bytes(&self) -> &[u8] {
            &self.main
        }
        fn revalidate_backup(&self, target: &Target) -> Result<()> {
            if let Some(old) = &self.receipt.intent.old {
                let name = c(OsStr::new(&self.receipt.intent.stage))?;
                if !same_displaced(
                    target.inspect_name(&name)?.as_ref(),
                    Some(&Generation {
                        entries: old.entries.clone(),
                    }),
                ) {
                    return Err(REFUSED);
                }
            }
            Ok(())
        }
        pub fn leaf_names(&self, target: &Target) -> Result<BTreeSet<PathBuf>> {
            self.revalidate_backup(target)?;
            let names = current_leaf_names(target, &self.receipt)?;
            self.revalidate_backup(target)?;
            Ok(names)
        }
        pub fn read_leaf(&self, target: &Target, path: &Path) -> Result<Zeroizing<Vec<u8>>> {
            self.revalidate_backup(target)?;
            let bytes = read_current_leaf(target, &self.receipt, path)?;
            self.revalidate_backup(target)?;
            Ok(bytes)
        }
        pub fn revalidate(
            &self,
            target: &Target,
            authority: &(impl ProjectionAdmission + ?Sized),
        ) -> Result<()> {
            authority.admit_projection_source(&self.source)?;
            self.revalidate_backup(target)?;
            revalidate_current_receipt(target, &self.receipt)?;
            projected_generation(
                self.receipt.generation(),
                &self.base_current,
                self.receipt.intent(),
            )
        }
        pub fn intent(&self) -> ProjectionIntent {
            ProjectionIntent {
                schema: "auto-config-projection-intent-v1".into(),
                base_record_sha256: self.source.base_record_sha256.clone(),
                intent: self.receipt.intent.clone(),
                base_current: GenerationWire {
                    entries: self.base_current.entries.clone(),
                },
                accepted: GenerationWire {
                    entries: self.receipt.current.entries.clone(),
                },
                main_sha256: self.main_sha256.clone(),
            }
        }
        /// Called only after actual renderer validates complete TOML semantics;
        /// typed proof is produced by its closed verifier adapter, not a boolean.
        pub fn accept(
            self,
            target: &Target,
            authority: &(impl ProjectionAdmission + ?Sized),
            proof: &crate::profile_auto_runtime_publication::linux::VerifiedProjection,
        ) -> Result<ProjectionReceipt> {
            self.revalidate(target, authority)?;
            proof.matches_source(&self.source, &self.main_sha256)?;
            Ok(ProjectionReceipt {
                intent: self.intent(),
                receipt: self.receipt,
            })
        }
    }
    pub(crate) struct ProjectionReceipt {
        intent: ProjectionIntent,
        receipt: PublicationReceipt,
    }
    impl ProjectionReceipt {
        pub fn intent(&self) -> &ProjectionIntent {
            &self.intent
        }
        pub fn source_record_sha256(&self) -> &str {
            &self.intent.base_record_sha256
        }
        pub fn owned_current(&self) -> &PublicationReceipt {
            &self.receipt
        }
        pub fn durable_bytes(&self, binding: RecordBinding) -> Result<Vec<u8>> {
            if !valid_binding(&binding) || binding.phase != "projection" {
                return Err(REFUSED);
            }
            serde_json::to_vec(&DurableRecord::Projection {
                binding,
                base_record_sha256: self.intent.base_record_sha256.clone(),
                intent: self.receipt.intent.clone(),
                base_current: self.intent.base_current.clone(),
                accepted: GenerationWire {
                    entries: self.receipt.current.entries.clone(),
                },
                main_sha256: self.intent.main_sha256.clone(),
            })
            .map_err(|_| REFUSED)
        }
    }
    pub(crate) fn reopen_own_receipt(
        target: &Target,
        record: &AuthenticatedRecord,
    ) -> Result<PublicationReceipt> {
        record.recheck_stage()?;
        let (intent, current, projection) = match &record.record {
            DurableRecord::Publication {
                intent, current, ..
            } => (intent, current, None),
            DurableRecord::Projection {
                binding,
                base_record_sha256,
                intent,
                base_current,
                accepted,
                main_sha256,
            } => {
                if binding.phase != "projection"
                    || base_record_sha256.len() != 64
                    || !base_record_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    || main_sha256.len() != 64
                    || !main_sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(REFUSED);
                }
                (intent, accepted, Some((base_current, main_sha256)))
            }
            _ => return Err(REFUSED),
        };
        validate_intent_shape(target, intent)?;
        let current = Generation {
            entries: current.entries.clone(),
        };
        if target.inspect()?.as_ref() != Some(&current) {
            return Err(REFUSED);
        }
        if let Some((base, _)) = projection {
            projected_generation(
                &current,
                &Generation {
                    entries: base.entries.clone(),
                },
                intent,
            )?;
        } else if !same_new(
            &current,
            &Generation {
                entries: intent.new_tree.entries.clone(),
            },
            intent.service_uid,
            intent.service_gid,
            intent.root_mode,
        ) {
            return Err(REFUSED);
        }
        let root = dir(target.parent.as_raw_fd(), &target.leaf)?;
        if identity(&stat(root.as_raw_fd())?) != intent.new_root {
            return Err(REFUSED);
        }
        let old_root = if let Some(old) = &intent.old {
            let stage = c(OsStr::new(&intent.stage))?;
            let old = Generation {
                entries: old.entries.clone(),
            };
            if !same_displaced(target.inspect_name(&stage)?.as_ref(), Some(&old)) {
                return Err(REFUSED);
            }
            Some(dir(target.parent.as_raw_fd(), &stage)?)
        } else {
            None
        };
        let receipt = PublicationReceipt {
            intent: intent.clone(),
            current,
            root,
            old_root,
        };
        revalidate_current_receipt(target, &receipt)?;
        if let Some((_, expected_sha)) = projection {
            let bytes = read_current_leaf(target, &receipt, Path::new("aegis.toml"))?;
            if format!("{:x}", Sha256::digest(bytes.as_slice())) != *expected_sha {
                return Err(REFUSED);
            }
        }
        Ok(receipt)
    }
    fn validate_intent_shape(target: &Target, intent: &PublicationIntent) -> Result<()> {
        target.revalidate_namespace()?;
        if intent.root_mode == RootMode::RetainedOriginalTree {
            let original = Generation {
                entries: intent.new_tree.entries.clone(),
            };
            admit_supported_original_runtime_state(&original)?;
            let root = original.entries.get(Path::new("")).ok_or(REFUSED)?;
            if intent.old.is_none()
                || root.id != intent.new_root
                || root.uid != intent.service_uid
                || root.gid != intent.service_gid
            {
                return Err(REFUSED);
            }
        }
        if matches!(
            intent.root_mode,
            RootMode::RuntimeConfig0700 | RootMode::RuntimeConfig0750
        ) && intent.service_uid != 0
        {
            return Err(REFUSED);
        }
        if intent.root_mode == RootMode::AdministratorMetadata0700
            && (intent.service_uid != 0 || intent.service_gid != 0)
        {
            return Err(REFUSED);
        }
        if intent.protocol != "auto-config-publication-v1"
            || intent.target != target.path
            || intent.parent != identity(&stat(target.parent.as_raw_fd())?)
            || intent.epoch != intent.stage
            || !intent.stage.starts_with(".auto-config-")
            || intent.stage.len() != 45
            || !intent.stage[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(REFUSED);
        }
        Ok(())
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct WithdrawalIntent {
        protocol: String,
        target: PathBuf,
        parent: Identity,
        retired_name: String,
        root: Identity,
        current: GenerationWire,
        publication_epoch: String,
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WithdrawalIntentRecord {
        schema: String,
        binding: RecordBinding,
        intent: WithdrawalIntent,
    }
    impl WithdrawalIntent {
        pub(crate) fn target(&self) -> &Path {
            &self.target
        }
        pub(crate) fn publication_epoch(&self) -> &str {
            &self.publication_epoch
        }
        pub(crate) fn durable_bytes(&self, binding: RecordBinding) -> Result<Vec<u8>> {
            if !valid_binding(&binding) || binding.phase != "rollback" {
                return Err(REFUSED);
            }
            serde_json::to_vec(&WithdrawalIntentRecord {
                schema: "auto-config-withdrawal-intent-v1".into(),
                binding,
                intent: self.clone(),
            })
            .map_err(|_| REFUSED)
        }
    }
    /// No JSON constructor. Owns admitted private transaction-stage descriptor
    /// and required positively validated Store pending-phase/hash-chain claim.
    pub(crate) struct AuthenticatedWithdrawalIntent {
        stage: OwnedFd,
        stage_id: Identity,
        record: WithdrawalIntentRecord,
        hash: String,
    }
    impl AuthenticatedWithdrawalIntent {
        /// Fresh protected pending-role/epoch/hash-chain admission is required
        /// at recovery boundaries; a prior admission is never a current lease.
        pub(crate) fn revalidate_authority(
            &self,
            authority: &(impl PhaseAuthority + ?Sized),
        ) -> Result<()> {
            self.recheck_stage()?;
            let stage = stat(self.stage.as_raw_fd())?;
            authority.validate_record_claim(&RecordClaim {
                actual_stage: identity(&stage),
                administrator_uid: stage.st_uid,
                record_leaf: "withdrawal-intent.json".into(),
                record_sha256: self.hash.clone(),
                binding: self.record.binding.clone(),
            })?;
            self.recheck_stage()
        }
        pub fn record_hash(&self) -> &str {
            &self.hash
        }
        fn recheck_stage(&self) -> Result<()> {
            let s = stat(self.stage.as_raw_fd())?;
            if identity(&s) != self.stage_id
                || s.st_uid != unsafe { libc::geteuid() }
                || s.st_mode & 0o777 != 0o700
            {
                return Err(REFUSED);
            }
            // Revalidate the actual immutable protected pending intent bytes,
            // not merely its stage directory. Selected original input paths are
            // never read here. Preserve exact PhaseAuthority-pinned raw hash.
            let leaf = c(OsStr::new("withdrawal-intent.json"))?;
            let held = fd(unsafe {
                libc::openat(
                    self.stage.as_raw_fd(),
                    leaf.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            })?;
            let before = stat(held.as_raw_fd())?;
            if before.st_mode != (libc::S_IFREG | 0o600)
                || before.st_uid != s.st_uid
                || before.st_nlink != 1
                || before.st_size < 0
                || before.st_size > 4 * 1024 * 1024
            {
                return Err(REFUSED);
            }
            let mut file = File::from(held);
            let mut bytes = Zeroizing::new(Vec::new());
            (&mut file)
                .take(4 * 1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| REFUSED)?;
            if bytes.len() > 4 * 1024 * 1024
                || metadata(&stat(file.as_raw_fd())?) != metadata(&before)
                || format!("{:x}", Sha256::digest(bytes.as_slice())) != self.record_hash()
            {
                return Err(REFUSED);
            }
            Ok(())
        }
    }
    pub(crate) fn authenticate_withdrawal_intent(
        stage: OwnedFd,
        authority: &(impl PhaseAuthority + ?Sized),
    ) -> Result<AuthenticatedWithdrawalIntent> {
        let admin = unsafe { libc::geteuid() };
        let ss = stat(stage.as_raw_fd())?;
        if ss.st_mode & libc::S_IFMT != libc::S_IFDIR
            || ss.st_uid != admin
            || ss.st_mode & 0o777 != 0o700
        {
            return Err(REFUSED);
        }
        let name = c(OsStr::new("withdrawal-intent.json"))?;
        let fd = fd(unsafe {
            libc::openat(
                stage.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        })?;
        let fs = stat(fd.as_raw_fd())?;
        if fs.st_mode != (libc::S_IFREG | 0o600)
            || fs.st_uid != admin
            || fs.st_mode & 0o777 != 0o600
            || fs.st_nlink != 1
            || fs.st_size < 0
            || fs.st_size > 4 * 1024 * 1024
        {
            return Err(REFUSED);
        }
        let mut file = File::from(fd);
        let mut bytes = Zeroizing::new(Vec::new());
        (&mut file)
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| REFUSED)?;
        if bytes.len() > 4 * 1024 * 1024 || metadata(&stat(file.as_raw_fd())?) != metadata(&fs) {
            return Err(REFUSED);
        }
        let record: WithdrawalIntentRecord = serde_json::from_slice(&bytes).map_err(|_| REFUSED)?;
        if record.schema != "auto-config-withdrawal-intent-v1"
            || !valid_binding(&record.binding)
            || record.binding.phase != "rollback"
            || record.binding.transaction_stage != identity(&ss)
        {
            return Err(REFUSED);
        }
        let hash = format!("{:x}", Sha256::digest(bytes.as_slice()));
        // Store must require Header.pending: exact current role, phase, stage
        // identity/nonce and this hash. No default authority implementation.
        authority.validate_record_claim(&RecordClaim {
            actual_stage: identity(&ss),
            administrator_uid: admin,
            record_leaf: "withdrawal-intent.json".into(),
            record_sha256: hash.clone(),
            binding: record.binding.clone(),
        })?;
        Ok(AuthenticatedWithdrawalIntent {
            stage,
            stage_id: identity(&ss),
            record,
            hash,
        })
    }
    /// Read-only reconciliation of an authenticated interrupted withdrawal.
    /// None means the rename never occurred. A receipt is minted only from
    /// the actual held retired directory, never from serialized generations.
    pub(crate) fn recover_withdrawal_receipt(
        target: &Target,
        pending: &AuthenticatedWithdrawalIntent,
        authority: &(impl PhaseAuthority + ?Sized),
    ) -> Result<Option<WithdrawalReceipt>> {
        pending.revalidate_authority(authority)?;
        let intent = &pending.record.intent;
        match classify_withdrawal(target, intent)? {
            RetirementState::BeforeRetirement => {
                pending.revalidate_authority(authority)?;
                if classify_withdrawal(target, intent)? != RetirementState::BeforeRetirement {
                    return Err(REFUSED);
                }
                pending.revalidate_authority(authority)?;
                Ok(None)
            }
            RetirementState::OriginalAbsenceRestored => {
                let name = c(OsStr::new(&intent.retired_name))?;
                let root = dir(target.parent.as_raw_fd(), &name)?;
                if identity(&stat(root.as_raw_fd())?) != intent.root {
                    return Err(REFUSED);
                }
                let mut entries = BTreeMap::new();
                let mut total = 0;
                scan(root.as_raw_fd(), Path::new(""), 0, &mut entries, &mut total)?;
                let retired = Generation { entries };
                let original = Generation {
                    entries: intent.current.entries.clone(),
                };
                if !same_displaced(Some(&retired), Some(&original)) {
                    return Err(REFUSED);
                }
                let receipt = WithdrawalReceipt {
                    intent: intent.clone(),
                    retired,
                    root,
                };
                receipt.revalidate_held_retired()?;
                revalidate_withdrawal(target, &receipt)?;
                pending.revalidate_authority(authority)?;
                revalidate_withdrawal(target, &receipt)?;
                Ok(Some(receipt))
            }
        }
    }
    /// New configuration is retained intact; no chmod/chown/delete occurs.
    /// It can remain readable to the service UID under its prior 0750/0600
    /// permissions, but its parent remains administrative and non-writable.
    pub(crate) struct WithdrawalReceipt {
        intent: WithdrawalIntent,
        retired: Generation,
        root: OwnedFd,
    }
    impl WithdrawalReceipt {
        pub fn intent(&self) -> &WithdrawalIntent {
            &self.intent
        }
        fn revalidate_held_retired(&self) -> Result<()> {
            if identity(&stat(self.root.as_raw_fd())?) != self.intent.root {
                return Err(REFUSED);
            }
            let mut entries = BTreeMap::new();
            let mut total = 0;
            scan(
                self.root.as_raw_fd(),
                Path::new(""),
                0,
                &mut entries,
                &mut total,
            )?;
            if entries != self.retired.entries {
                return Err(REFUSED);
            }
            Ok(())
        }
        pub fn durable_bytes(&self, binding: RecordBinding) -> Result<Vec<u8>> {
            if !valid_binding(&binding) {
                return Err(REFUSED);
            }
            self.revalidate_held_retired()?;
            let bytes = serde_json::to_vec(&DurableRecord::Withdrawal {
                binding,
                intent: self.intent.clone(),
                retired: GenerationWire {
                    entries: self.retired.entries.clone(),
                },
            })
            .map_err(|_| REFUSED)?;
            self.revalidate_held_retired()?;
            Ok(bytes)
        }
        #[cfg(test)]
        pub fn retained_name(&self) -> &str {
            &self.intent.retired_name
        }
    }
    pub(crate) trait OwnAbsenceChainAuthority {
        /// Actual protected header original kind2 and all owned role epochs to
        /// the exact current receipt must be bound. No default/no-op authority.
        fn validate_original_absence_and_chain(
            &self,
            target: &Path,
            current_epoch: &str,
        ) -> Result<()>;
    }
    #[cfg(test)]
    pub(crate) fn restore_original_absence(
        target: &Target,
        own: &PublicationReceipt,
        persist: impl FnMut(&WithdrawalIntent) -> Result<()>,
    ) -> Result<WithdrawalReceipt> {
        if own.intent.old.is_some() {
            return Err(REFUSED);
        }
        retire_own_current(target, own, persist, || Ok(()))
    }
    pub(crate) fn restore_original_absence_after_own_chain(
        target: &Target,
        own: &PublicationReceipt,
        authority: &(impl OwnAbsenceChainAuthority + ?Sized),
        persist: impl FnMut(&WithdrawalIntent) -> Result<()>,
    ) -> Result<WithdrawalReceipt> {
        authority.validate_original_absence_and_chain(&target.path, &own.intent.epoch)?;
        retire_own_current(target, own, persist, || {
            authority.validate_original_absence_and_chain(&target.path, &own.intent.epoch)
        })
    }
    fn retire_own_current(
        target: &Target,
        own: &PublicationReceipt,
        mut persist: impl FnMut(&WithdrawalIntent) -> Result<()>,
        recheck_chain: impl FnOnce() -> Result<()>,
    ) -> Result<WithdrawalReceipt> {
        revalidate_current_receipt(target, own)?;
        let retired_name = random_name();
        let intent = WithdrawalIntent {
            protocol: "auto-config-withdrawal-v1".into(),
            target: target.path.clone(),
            parent: identity(&stat(target.parent.as_raw_fd())?),
            retired_name: retired_name.to_str().map_err(|_| REFUSED)?.into(),
            root: own.intent.new_root.clone(),
            current: GenerationWire {
                entries: own.current.entries.clone(),
            },
            publication_epoch: own.intent.epoch.clone(),
        };
        persist(&intent)?;
        recheck_chain()?;
        revalidate_current_receipt(target, own)?;
        rename(
            target.parent.as_raw_fd(),
            &target.leaf,
            &retired_name,
            libc::RENAME_NOREPLACE,
        )?;
        sync(target.parent.as_raw_fd())?;
        target.revalidate_namespace()?;
        if target.inspect()?.is_some() {
            return Err(REFUSED);
        }
        let retired = target.inspect_name(&retired_name)?.ok_or(REFUSED)?;
        if !same_displaced(Some(&retired), Some(&own.current)) {
            return Err(REFUSED);
        }
        let root = dir(target.parent.as_raw_fd(), &retired_name)?;
        if identity(&stat(root.as_raw_fd())?) != intent.root {
            return Err(REFUSED);
        }
        Ok(WithdrawalReceipt {
            intent,
            retired,
            root,
        })
    }
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum RetirementState {
        BeforeRetirement,
        OriginalAbsenceRestored,
    }
    pub(crate) fn classify_withdrawal(
        target: &Target,
        intent: &WithdrawalIntent,
    ) -> Result<RetirementState> {
        target.revalidate_namespace()?;
        if intent.protocol != "auto-config-withdrawal-v1"
            || intent.target != target.path
            || intent.parent != identity(&stat(target.parent.as_raw_fd())?)
            || intent.current.entries.get(Path::new("")).map(|m| &m.id) != Some(&intent.root)
            || !intent.publication_epoch.starts_with(".auto-config-")
            || intent.publication_epoch.len() != 45
            || !intent.publication_epoch[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || !intent.retired_name.starts_with(".auto-config-")
            || intent.retired_name.len() != 45
            || !intent.retired_name[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(REFUSED);
        }
        let name = c(OsStr::new(&intent.retired_name))?;
        let current = Generation {
            entries: intent.current.entries.clone(),
        };
        let target_now = target.inspect()?;
        let retired = target.inspect_name(&name)?;
        if target_now.as_ref() == Some(&current) && retired.is_none() {
            return Ok(RetirementState::BeforeRetirement);
        }
        if target_now.is_none()
            && same_displaced(retired.as_ref(), Some(&current))
            && retired
                .as_ref()
                .and_then(|g| g.entries.get(Path::new("")))
                .map(|m| &m.id)
                == Some(&intent.root)
        {
            return Ok(RetirementState::OriginalAbsenceRestored);
        }
        Err(REFUSED)
    }
    pub(crate) fn reopen_withdrawal_receipt(
        target: &Target,
        record: &AuthenticatedRecord,
    ) -> Result<WithdrawalReceipt> {
        record.recheck_stage()?;
        let DurableRecord::Withdrawal {
            intent, retired, ..
        } = &record.record
        else {
            return Err(REFUSED);
        };
        target.revalidate_namespace()?;
        if intent.protocol != "auto-config-withdrawal-v1"
            || intent.target != target.path
            || intent.parent != identity(&stat(target.parent.as_raw_fd())?)
            || intent.current.entries.get(Path::new("")).map(|m| &m.id) != Some(&intent.root)
            || !intent.publication_epoch.starts_with(".auto-config-")
            || intent.publication_epoch.len() != 45
            || !intent.publication_epoch[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || target.inspect()?.is_some()
            || !intent.retired_name.starts_with(".auto-config-")
            || intent.retired_name.len() != 45
            || !intent.retired_name[13..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(REFUSED);
        }
        let name = c(OsStr::new(&intent.retired_name))?;
        let actual = target.inspect_name(&name)?.ok_or(REFUSED)?;
        if actual.entries != retired.entries
            || !same_displaced(
                Some(&actual),
                Some(&Generation {
                    entries: intent.current.entries.clone(),
                }),
            )
        {
            return Err(REFUSED);
        }
        let root = dir(target.parent.as_raw_fd(), &name)?;
        if identity(&stat(root.as_raw_fd())?) != intent.root {
            return Err(REFUSED);
        }
        let receipt = WithdrawalReceipt {
            intent: intent.clone(),
            retired: actual,
            root,
        };
        receipt.revalidate_held_retired()?;
        revalidate_withdrawal(target, &receipt)?;
        record.recheck_stage()?;
        Ok(receipt)
    }
    pub(crate) fn revalidate_withdrawal(target: &Target, own: &WithdrawalReceipt) -> Result<()> {
        target.revalidate_namespace()?;
        if target.path != own.intent.target
            || identity(&stat(target.parent.as_raw_fd())?) != own.intent.parent
            || identity(&stat(own.root.as_raw_fd())?) != own.intent.root
            || target.inspect()?.is_some()
            || target
                .inspect_name(&c(OsStr::new(&own.intent.retired_name))?)?
                .as_ref()
                != Some(&own.retired)
        {
            return Err(REFUSED);
        }
        Ok(())
    }
    /// Metadata-only interrupted-call classification. Caller must load intent
    /// from its authenticated administrator-private durable store; arbitrary
    /// JSON is not sufficient. No filesystem changes are made here.
    #[derive(Debug, PartialEq, Eq)]
    pub(crate) enum InterruptedState {
        BeforeRename,
        PublishedNeedsAcceptance,
    }
    pub(crate) fn classify_interrupted(
        target: &Target,
        intent: &PublicationIntent,
    ) -> Result<InterruptedState> {
        validate_intent_shape(target, intent)?;
        let stage = CString::new(intent.stage.as_str()).map_err(|_| REFUSED)?;
        let now = target.inspect()?;
        let staged = target.inspect_name(&stage)?;
        let old = intent.old.as_ref().map(|x| Generation {
            entries: x.entries.clone(),
        });
        if now == old
            && staged.as_ref()
                == Some(&Generation {
                    entries: intent.new_tree.entries.clone(),
                })
        {
            return Ok(InterruptedState::BeforeRename);
        }
        if now
            .as_ref()
            .map(|g| {
                same_new_or_private(
                    g,
                    &Generation {
                        entries: intent.new_tree.entries.clone(),
                    },
                    intent.service_uid,
                    intent.service_gid,
                    intent.root_mode,
                )
            })
            .unwrap_or(false)
            && same_displaced(staged.as_ref(), old.as_ref())
        {
            return Ok(InterruptedState::PublishedNeedsAcceptance);
        }
        Err(REFUSED)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::collections::{BTreeMap, BTreeSet};
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::path::{Path, PathBuf};

        #[test]
        fn systemd_dropin_public_mode_is_path_and_owner_bound() {
            let mut root: libc::stat = unsafe { std::mem::zeroed() };
            root.st_mode = libc::S_IFDIR | 0o700;
            let mut leaf: libc::stat = unsafe { std::mem::zeroed() };
            leaf.st_mode = libc::S_IFREG | 0o644;
            leaf.st_nlink = 1;
            let mut generation = Generation {
                entries: BTreeMap::from([
                    (PathBuf::new(), metadata(&root)),
                    (PathBuf::from("10-dedicated-uid.conf"), metadata(&leaf)),
                ]),
            };
            assert!(
                root_owned_config_tree_exact(&generation, Path::new(SYSTEMD_DROPIN_TARGET)).is_ok()
            );
            assert!(
                root_owned_config_tree_exact(&generation, Path::new("/private/config")).is_err()
            );
            generation
                .entries
                .get_mut(Path::new("10-dedicated-uid.conf"))
                .unwrap()
                .mode = libc::S_IFREG | 0o666;
            assert!(
                root_owned_config_tree_exact(&generation, Path::new(SYSTEMD_DROPIN_TARGET))
                    .is_err()
            );
            generation
                .entries
                .get_mut(Path::new("10-dedicated-uid.conf"))
                .unwrap()
                .mode = libc::S_IFREG | 0o644;
            generation
                .entries
                .get_mut(Path::new("10-dedicated-uid.conf"))
                .unwrap()
                .uid = 1000;
            assert!(
                root_owned_config_tree_exact(&generation, Path::new(SYSTEMD_DROPIN_TARGET))
                    .is_err()
            );
        }
        #[test]
        fn native_link_count_metadata_preserves_zero_and_full_width() {
            // Pure stat-to-witness conversion: no filesystem or privilege use.
            let mut native: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(metadata(&native).links, 0);
            native.st_nlink = libc::nlink_t::MAX;
            let expected = match std::mem::size_of::<libc::nlink_t>() {
                4 => u64::from(u32::MAX),
                8 => u64::MAX,
                _ => panic!("unsupported native link-count width"),
            };
            assert_eq!(metadata(&native).links, expected);
        }

        #[test]
        fn runtime_leaf_policy_separates_public_credentials_and_retained_admin() {
            let p = ConfigPolicy {
                runtime_uid: 997,
                runtime_gid: 997,
                root_policy: false,
                leaves: BTreeMap::new(),
            };
            assert_eq!(p.attributes(ConfigLeafRole::Public), (0, 997, 0o640));
            assert_eq!(
                p.attributes(ConfigLeafRole::RuntimePrivate),
                (997, 997, 0o600)
            );
            assert_eq!(
                p.attributes(ConfigLeafRole::AdministratorPrivate),
                (0, 0, 0o600)
            );
            let root = ConfigPolicy {
                runtime_uid: 0,
                runtime_gid: 0,
                root_policy: true,
                leaves: BTreeMap::new(),
            };
            assert_eq!(root.attributes(ConfigLeafRole::Public), (0, 0, 0o600));
            assert_eq!(
                root.attributes(ConfigLeafRole::SystemdDropin),
                (0, 0, 0o644)
            );
        }
        #[test]
        #[ignore = "requires actual Linux root descriptor/ownership QA"]
        fn runtime_mixed_policy_readback_binds_actual_fresh_inodes_and_refuses_missing_role() {
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let f = Private::new();
            let tree = Private::tree(b"synthetic public settings");
            let roles = BTreeMap::from([
                (PathBuf::from("a.conf"), ConfigLeafRole::Public),
                (
                    PathBuf::from("nested/b.conf"),
                    ConfigLeafRole::RuntimePrivate,
                ),
            ]);
            let policy = ConfigPolicy {
                runtime_uid: 997,
                runtime_gid: 997,
                root_policy: false,
                leaves: roles,
            };
            let prepared = Prepared::build_policy_inner(
                Target::open(&f.path()).unwrap(),
                None,
                &tree,
                0,
                997,
                RootMode::RuntimeConfig0750,
                |_| Ok(()),
                Some(&policy),
            )
            .unwrap();
            let receipt = prepared.publish(|_| Ok(()), |_, _| Ok(())).unwrap();
            let target = Target::open(&f.path()).unwrap();
            verify_runtime_config_policy(&target, &receipt, &policy).unwrap();
            assert_eq!(
                read_current_leaf(&target, &receipt, Path::new("a.conf"))
                    .unwrap()
                    .as_slice(),
                b"synthetic public settings"
            );
            let before = target.inspect().unwrap();
            let incomplete = ConfigPolicy {
                runtime_uid: 997,
                runtime_gid: 997,
                root_policy: false,
                leaves: BTreeMap::new(),
            };
            assert!(Prepared::build_policy_inner(
                Target::open(&f.path()).unwrap(),
                before.clone(),
                &tree,
                0,
                997,
                RootMode::RuntimeConfig0750,
                |_| panic!("must refuse before stage creation"),
                Some(&incomplete)
            )
            .is_err());
            assert_eq!(target.inspect().unwrap(), before);
            assert!(verify_runtime_config_policy(&target, &receipt, &incomplete).is_err());
        }
        struct Private {
            base: PathBuf,
        }
        impl Private {
            fn new() -> Self {
                // /tmp is allowed solely as root-owned sticky ancestor, never
                // final target parent; the test creates a private 0700 child.
                let home = PathBuf::from("/tmp");
                let bytes: [u8; 16] = rand::random();
                let suffix = bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
                let base = home.join(format!(".aegis-auto-publication-test-{suffix}"));
                std::fs::create_dir(&base).unwrap();
                std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
                Self { base }
            }
            fn path(&self) -> PathBuf {
                self.base.join("config")
            }
            fn ids(&self) -> (u32, u32) {
                unsafe { (libc::geteuid(), libc::getegid()) }
            }
            fn tree(bytes: &[u8]) -> CapturedTree {
                CapturedTree::new(
                    BTreeMap::from([
                        (PathBuf::from("a.conf"), bytes.to_vec()),
                        (PathBuf::from("nested/b.conf"), b"second".to_vec()),
                    ]),
                    BTreeSet::from([PathBuf::from("empty/child")]),
                )
                .unwrap()
            }
            fn prepare(&self, tree: &CapturedTree) -> Prepared {
                let target = Target::open(&self.path()).unwrap();
                let generation = target.inspect().unwrap();
                let (uid, gid) = self.ids();
                Prepared::build(target, generation, tree, uid, gid, |_| Ok(())).unwrap()
            }
        }
        impl Drop for Private {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.base);
            }
        }
        #[test]
        fn publishes_complete_bytes_and_empty_dirs() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"captured"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"captured");
            assert!(f.path().join("empty/child").is_dir());
            assert_eq!(
                std::fs::metadata(f.path().join("a.conf"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(f.path()).unwrap().permissions().mode() & 0o777,
                0o750
            );
            revalidate_current_receipt(&Target::open(&f.path()).unwrap(), &r).unwrap();
        }
        #[test]
        fn exchange_retains_old_backup_and_restores_only_captured_bytes() {
            let f = Private::new();
            f.prepare(&Private::tree(b"old"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            assert_eq!(
                std::fs::read(f.base.join(&r.intent().stage).join("a.conf")).unwrap(),
                b"old"
            );
            let (uid, gid) = f.ids();
            let restored = restore_captured(
                Target::open(&f.path()).unwrap(),
                &r,
                &Private::tree(b"immutable-old"),
                uid,
                gid,
                |_| Ok(()),
                |_| Ok(()),
            )
            .unwrap();
            assert_eq!(
                std::fs::read(f.path().join("a.conf")).unwrap(),
                b"immutable-old"
            );
            revalidate_current_receipt(&Target::open(&f.path()).unwrap(), &restored).unwrap();
        }
        #[test]
        fn symlink_target_refuses_and_victim_stays_unchanged() {
            let f = Private::new();
            let victim = f.base.join("victim");
            std::fs::create_dir(&victim).unwrap();
            std::fs::write(victim.join("proof"), b"victim").unwrap();
            symlink(&victim, f.path()).unwrap();
            assert!(Target::open(&f.path()).unwrap().inspect().is_err());
            assert_eq!(std::fs::read(victim.join("proof")).unwrap(), b"victim");
        }
        #[test]
        fn hardlinked_original_file_refuses() {
            let f = Private::new();
            std::fs::create_dir(f.path()).unwrap();
            let victim = f.base.join("victim");
            std::fs::write(&victim, b"victim").unwrap();
            std::fs::hard_link(&victim, f.path().join("a.conf")).unwrap();
            assert!(Target::open(&f.path()).unwrap().inspect().is_err());
            assert_eq!(std::fs::read(victim).unwrap(), b"victim");
        }
        #[test]
        fn target_replacement_before_publish_refuses() {
            let f = Private::new();
            f.prepare(&Private::tree(b"old"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let p = f.prepare(&Private::tree(b"new"));
            std::fs::rename(f.path(), f.base.join("saved")).unwrap();
            std::fs::create_dir(f.path()).unwrap();
            std::fs::write(f.path().join("victim"), b"untouched").unwrap();
            assert!(p.publish(|_| Ok(()), |_, _| Ok(())).is_err());
            assert_eq!(
                std::fs::read(f.path().join("victim")).unwrap(),
                b"untouched"
            );
        }
        #[test]
        fn renamed_parent_and_symlink_substitution_cannot_write_victim() {
            let f = Private::new();
            let p = f.prepare(&Private::tree(b"new"));
            let moved = f.base.with_extension("moved");
            let victim = f.base.with_extension("victim");
            std::fs::create_dir(&victim).unwrap();
            std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::write(victim.join("proof"), b"victim").unwrap();
            std::fs::rename(&f.base, &moved).unwrap();
            symlink(&victim, &f.base).unwrap();
            assert!(p.publish(|_| Ok(()), |_, _| Ok(())).is_err());
            assert!(!victim.join("config").exists());
            assert_eq!(std::fs::read(victim.join("proof")).unwrap(), b"victim");
            std::fs::remove_file(&f.base).unwrap();
            std::fs::rename(moved, &f.base).unwrap();
            std::fs::remove_dir_all(victim).unwrap();
        }
        #[test]
        fn persistence_failure_keeps_original_and_prepared_tree() {
            let f = Private::new();
            f.prepare(&Private::tree(b"old"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let p = f.prepare(&Private::tree(b"new"));
            let stage = p.intent().unwrap().stage;
            assert!(p
                .publish(|_| Err("injected durable intent failure"), |_, _| Ok(()))
                .is_err());
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"old");
            assert_eq!(
                std::fs::read(f.base.join(stage).join("a.conf")).unwrap(),
                b"new"
            );
        }
        #[test]
        fn interrupted_exchange_classifies_without_changing_bytes() {
            let f = Private::new();
            f.prepare(&Private::tree(b"old"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let p = f.prepare(&Private::tree(b"new"));
            let i = p.intent().unwrap();
            assert_eq!(
                classify_interrupted(&Target::open(&f.path()).unwrap(), &i).unwrap(),
                InterruptedState::BeforeRename
            );
            let r = p.publish(|_| Ok(()), |_, _| Ok(())).unwrap();
            assert_eq!(
                classify_interrupted(&Target::open(&f.path()).unwrap(), r.intent()).unwrap(),
                InterruptedState::PublishedNeedsAcceptance
            );
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"new");
        }
        #[test]
        fn changed_current_refuses_restore_and_preserves_unrelated_file() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            std::fs::write(f.path().join("a.conf"), b"foreign").unwrap();
            let (uid, gid) = f.ids();
            assert!(restore_captured(
                Target::open(&f.path()).unwrap(),
                &r,
                &Private::tree(b"old"),
                uid,
                gid,
                |_| Ok(()),
                |_| Ok(())
            )
            .is_err());
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"foreign");
        }
        #[test]
        fn aliases_overlap_and_limits_refuse() {
            let f = Private::new();
            assert!(Target::open(Path::new("/")).is_err());
            assert!(Target::open(&f.base.join("./config")).is_err());
            let t = Target::open(&f.path()).unwrap();
            assert!(t.reject_overlap(&f.path().join("state")).is_err());
            assert!(CapturedTree::new(
                BTreeMap::from([(PathBuf::from("../victim"), vec![])]),
                BTreeSet::new()
            )
            .is_err());
            assert!(CapturedTree::new(
                BTreeMap::from([(PathBuf::from("a"), vec![0; 16 * 1024 * 1024 + 1])]),
                BTreeSet::new()
            )
            .is_err());
            assert!(CapturedTree::new(
                BTreeMap::from([(PathBuf::from("a"), vec![]), (PathBuf::from("a/b"), vec![])]),
                BTreeSet::new()
            )
            .is_err());
        }
        struct TestAuthority {
            stage: Identity,
            phase: String,
            hash: String,
            nonce: String,
            chain: String,
        }
        impl PhaseAuthority for TestAuthority {
            fn validate_record_claim(&self, c: &RecordClaim) -> Result<()> {
                // Exact test protected-store expected values; no unconditional pass.
                if c.actual_stage == self.stage
                    && c.binding.transaction_stage == self.stage
                    && c.binding.phase == self.phase
                    && c.record_sha256 == self.hash
                    && c.binding.transaction_nonce == self.nonce
                    && c.binding.chain_sha256 == self.chain
                {
                    Ok(())
                } else {
                    Err("test phase chain mismatch")
                }
            }
        }
        fn stage_record(
            f: &Private,
            bytes: impl FnOnce(RecordBinding) -> Vec<u8>,
            leaf: &str,
        ) -> (OwnedFd, TestAuthority) {
            let stage = f.base.join(format!("store-{}", leaf));
            std::fs::create_dir(&stage).unwrap();
            std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = File::open(&stage).unwrap();
            let stage_fd: OwnedFd = file.into();
            let stage_id = identity(&stat(stage_fd.as_raw_fd()).unwrap());
            let binding = RecordBinding {
                transaction_stage: stage_id.clone(),
                transaction_nonce: "123456789012345678901234567890ab".into(),
                phase: "config".into(),
                chain_sha256: "a".repeat(64),
            };
            let content = bytes(binding.clone());
            let hash = format!("{:x}", Sha256::digest(&content));
            std::fs::write(stage.join(leaf), content).unwrap();
            std::fs::set_permissions(stage.join(leaf), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            (
                stage_fd,
                TestAuthority {
                    stage: stage_id,
                    phase: binding.phase,
                    hash,
                    nonce: binding.transaction_nonce,
                    chain: binding.chain_sha256,
                },
            )
        }
        fn actual_publication_semantics(receipt: &PublicationReceipt) -> String {
            let mut bytes = b"aegis-owned-unit-dropin-receipt-v1\0".to_vec();
            bytes.extend_from_slice(&serde_json::to_vec(receipt.intent()).unwrap());
            bytes.extend_from_slice(&receipt.generation().witness().unwrap());
            format!("{:x}", Sha256::digest(&bytes))
        }
        #[test]
        fn historical_publication_semantics_survive_actual_retained_restore_not_live_reopen() {
            let f = Private::new();
            let (uid, gid) = f.ids();
            runtime_state_version(&f, b"original", uid, gid);
            let forward = runtime_state_version(&f, b"replacement", uid, gid);
            let expected = actual_publication_semantics(&forward);
            let original = Generation {
                entries: forward.intent.old.as_ref().unwrap().entries.clone(),
            }
            .witness()
            .unwrap();
            let (stage, authority) = stage_record(
                &f,
                |b| forward.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            let admitted =
                authenticate_record(stage, "publication-receipt.json", &authority).unwrap();
            assert_eq!(admitted.publication_semantics_sha256().unwrap(), expected);
            assert_eq!(
                admitted
                    .original_generation()
                    .unwrap()
                    .unwrap()
                    .witness()
                    .unwrap(),
                original
            );
            let guard = ExpectedCapture {
                path: f.path(),
                witness: Some(forward.generation().witness().unwrap()),
            };
            let restored = restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &forward,
                |_| Ok(()),
                &guard,
            )
            .unwrap();
            validate_retained_restore_predecessor(&forward, &restored).unwrap();
            let restored_store = Private::new();
            let (stage, authority) = stage_record(
                &restored_store,
                |b| restored.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            let admitted_restored =
                authenticate_record(stage, "publication-receipt.json", &authority).unwrap();
            validate_authenticated_retained_restore_predecessor(&admitted, &admitted_restored)
                .unwrap();
            let mut expected_restoration = b"aegis-owned-unit-dropin-restoration-v1\0".to_vec();
            expected_restoration.extend_from_slice(expected.as_bytes());
            expected_restoration.push(1);
            expected_restoration.extend_from_slice(&serde_json::to_vec(restored.intent()).unwrap());
            expected_restoration.extend_from_slice(&restored.generation().witness().unwrap());
            assert_eq!(
                authenticated_unit_retained_restoration_semantics_sha256(
                    &admitted,
                    &admitted_restored
                )
                .unwrap(),
                format!("{:x}", Sha256::digest(&expected_restoration))
            );
            assert!(authenticated_unit_retained_restoration_semantics_sha256(
                &admitted_restored,
                &admitted
            )
            .is_err());
            assert!(validate_authenticated_retained_restore_predecessor(
                &admitted_restored,
                &admitted
            )
            .is_err());
            assert!(
                validate_authenticated_retained_restore_predecessor(&admitted, &admitted).is_err()
            );
            std::fs::write(
                restored_store
                    .base
                    .join("store-publication-receipt.json/publication-receipt.json"),
                b"changed",
            )
            .unwrap();
            assert!(validate_authenticated_retained_restore_predecessor(
                &admitted,
                &admitted_restored
            )
            .is_err());
            assert!(authenticated_unit_retained_restoration_semantics_sha256(
                &admitted,
                &admitted_restored
            )
            .is_err());
            assert!(reopen_own_receipt(&Target::open(&f.path()).unwrap(), &admitted).is_err());
            assert_eq!(admitted.publication_semantics_sha256().unwrap(), expected);
            assert_eq!(
                admitted
                    .original_generation()
                    .unwrap()
                    .unwrap()
                    .witness()
                    .unwrap(),
                original
            );
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"original");
        }
        #[test]
        fn historical_publication_semantics_refuse_changed_record_and_nonpublication() {
            let f = Private::new();
            let forward = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let (stage, authority) = stage_record(
                &f,
                |b| forward.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            let admitted =
                authenticate_record(stage, "publication-receipt.json", &authority).unwrap();
            assert_eq!(
                admitted.publication_semantics_sha256().unwrap(),
                actual_publication_semantics(&forward)
            );
            assert!(admitted.original_generation().unwrap().is_none());
            std::fs::write(
                f.base
                    .join("store-publication-receipt.json/publication-receipt.json"),
                b"changed",
            )
            .unwrap();
            assert!(admitted.publication_semantics_sha256().is_err());
            assert!(admitted.original_generation().is_err());
            let target = Target::open(&f.path()).unwrap();
            let retired = restore_original_absence(&target, &forward, |_| Ok(())).unwrap();
            let (stage, authority) = stage_record(
                &f,
                |b| retired.durable_bytes(b).unwrap(),
                "withdrawal-receipt.json",
            );
            let admitted =
                authenticate_record(stage, "withdrawal-receipt.json", &authority).unwrap();
            assert!(admitted.publication_semantics_sha256().is_err());
            assert!(admitted.original_generation().is_err());
        }
        #[test]
        fn own_receipt_reopens_only_from_bound_protected_record() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let (stage, a) = stage_record(
                &f,
                |b| r.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            let authenticated = authenticate_record(stage, "publication-receipt.json", &a).unwrap();
            let reopened =
                reopen_own_receipt(&Target::open(&f.path()).unwrap(), &authenticated).unwrap();
            revalidate_current_receipt(&Target::open(&f.path()).unwrap(), &reopened).unwrap();
        }
        #[test]
        fn changed_phase_or_chain_cannot_mint_receipt_proof() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let (stage, mut a) = stage_record(
                &f,
                |b| r.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            a.phase = "finalized".into();
            assert!(authenticate_record(stage, "publication-receipt.json", &a).is_err());
        }
        #[test]
        fn changed_current_after_reentry_refuses_reopened_receipt() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let (stage, a) = stage_record(
                &f,
                |b| r.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            let authenticated = authenticate_record(stage, "publication-receipt.json", &a).unwrap();
            std::fs::write(f.path().join("a.conf"), b"different").unwrap();
            assert!(reopen_own_receipt(&Target::open(&f.path()).unwrap(), &authenticated).is_err());
        }
        #[test]
        fn original_absence_restored_without_delete_and_fresh_wave_works() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let target = Target::open(&f.path()).unwrap();
            let retired = restore_original_absence(&target, &r, |i| {
                assert_eq!(
                    classify_withdrawal(&target, i).unwrap(),
                    RetirementState::BeforeRetirement
                );
                Ok(())
            })
            .unwrap();
            assert!(!f.path().exists());
            assert_eq!(
                std::fs::read(f.base.join(retired.retained_name()).join("a.conf")).unwrap(),
                b"new"
            );
            revalidate_withdrawal(&target, &retired).unwrap();
            assert_eq!(
                classify_withdrawal(&target, &retired.intent).unwrap(),
                RetirementState::OriginalAbsenceRestored
            );
            f.prepare(&Private::tree(b"fresh"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"fresh");
            assert!(revalidate_withdrawal(&target, &retired).is_err());
        }
        fn withdrawal_stage_record(
            f: &Private,
            bytes: impl FnOnce(RecordBinding) -> Vec<u8>,
            leaf: &str,
        ) -> (OwnedFd, TestAuthority) {
            let stage = f.base.join(format!("store-{}", leaf));
            std::fs::create_dir(&stage).unwrap();
            std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
            let file = File::open(&stage).unwrap();
            let stage_fd: OwnedFd = file.into();
            let stage_id = identity(&stat(stage_fd.as_raw_fd()).unwrap());
            let binding = RecordBinding {
                transaction_stage: stage_id.clone(),
                transaction_nonce: "123456789012345678901234567890ab".into(),
                phase: "rollback".into(),
                chain_sha256: "a".repeat(64),
            };
            let content = bytes(binding.clone());
            let hash = format!("{:x}", Sha256::digest(&content));
            std::fs::write(stage.join(leaf), content).unwrap();
            std::fs::set_permissions(stage.join(leaf), std::fs::Permissions::from_mode(0o600))
                .unwrap();
            (
                stage_fd,
                TestAuthority {
                    stage: stage_id,
                    phase: binding.phase,
                    hash,
                    nonce: binding.transaction_nonce,
                    chain: binding.chain_sha256,
                },
            )
        }

        #[test]
        fn pending_withdrawal_before_rename_is_authenticated_and_unmodified() {
            let f = Private::new();
            let own = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let target = Target::open(&f.path()).unwrap();
            let mut pending = None;
            assert!(restore_original_absence(&target, &own, |i| {
                pending = Some(withdrawal_stage_record(
                    &f,
                    |b| i.durable_bytes(b).unwrap(),
                    "withdrawal-intent.json",
                ));
                Err(REFUSED)
            })
            .is_err());
            let (stage, a) = pending.unwrap();
            let admitted = authenticate_withdrawal_intent(stage, &a).unwrap();
            assert!(recover_withdrawal_receipt(&target, &admitted, &a)
                .unwrap()
                .is_none());
            revalidate_current_receipt(&target, &own).unwrap();
        }
        #[test]
        fn pending_withdrawal_after_rename_reopens_actual_held_retired_tree() {
            use std::os::unix::fs::MetadataExt;
            let f = Private::new();
            let own = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let old = std::fs::metadata(f.path()).unwrap();
            let target = Target::open(&f.path()).unwrap();
            let mut pending = None;
            let retired = restore_original_absence(&target, &own, |i| {
                pending = Some(withdrawal_stage_record(
                    &f,
                    |b| i.durable_bytes(b).unwrap(),
                    "withdrawal-intent.json",
                ));
                Ok(())
            })
            .unwrap();
            let (stage, a) = pending.unwrap();
            let admitted = authenticate_withdrawal_intent(stage, &a).unwrap();
            let recovered = recover_withdrawal_receipt(&target, &admitted, &a)
                .unwrap()
                .unwrap();
            let revoked = TestAuthority {
                stage: a.stage.clone(),
                phase: a.phase.clone(),
                hash: "b".repeat(64),
                nonce: a.nonce.clone(),
                chain: a.chain.clone(),
            };
            assert!(recover_withdrawal_receipt(&target, &admitted, &revoked).is_err());
            revalidate_withdrawal(&target, &recovered).unwrap();
            assert!(!f.path().exists());
            let actual = std::fs::metadata(f.base.join(retired.retained_name())).unwrap();
            assert_eq!(
                (
                    actual.dev(),
                    actual.ino(),
                    actual.uid(),
                    actual.gid(),
                    actual.mode()
                ),
                (old.dev(), old.ino(), old.uid(), old.gid(), old.mode())
            );
            assert_eq!(
                std::fs::read(f.base.join(recovered.retained_name()).join("a.conf")).unwrap(),
                b"new"
            );
            std::fs::create_dir(f.path()).unwrap();
            assert!(recover_withdrawal_receipt(&target, &admitted, &a).is_err());
        }
        #[test]
        fn pending_withdrawal_rejects_changed_retired_attrs_and_pending_bytes() {
            let f = Private::new();
            let own = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let target = Target::open(&f.path()).unwrap();
            let mut pending = None;
            let retired = restore_original_absence(&target, &own, |i| {
                pending = Some(withdrawal_stage_record(
                    &f,
                    |b| i.durable_bytes(b).unwrap(),
                    "withdrawal-intent.json",
                ));
                Ok(())
            })
            .unwrap();
            let (stage, a) = pending.unwrap();
            let admitted = authenticate_withdrawal_intent(stage, &a).unwrap();
            std::fs::set_permissions(
                f.base.join(retired.retained_name()).join("a.conf"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            assert!(recover_withdrawal_receipt(&target, &admitted, &a).is_err());
            std::fs::write(
                f.base
                    .join("store-withdrawal-intent.json/withdrawal-intent.json"),
                b"changed",
            )
            .unwrap();
            assert!(admitted.recheck_stage().is_err());
        }
        #[test]
        fn pending_withdrawal_rejects_wrong_phase_hash_and_root_epoch() {
            let f = Private::new();
            let own = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let target = Target::open(&f.path()).unwrap();
            let mut pending = None;
            assert!(restore_original_absence(&target, &own, |i| {
                pending = Some(withdrawal_stage_record(
                    &f,
                    |b| i.durable_bytes(b).unwrap(),
                    "withdrawal-intent.json",
                ));
                Err(REFUSED)
            })
            .is_err());
            let (stage, mut a) = pending.unwrap();
            a.phase = "state".into();
            assert!(authenticate_withdrawal_intent(stage, &a).is_err());
            a.phase = "rollback".into();
            a.hash = "b".repeat(64);
            let reopened: OwnedFd = File::open(f.base.join("store-withdrawal-intent.json"))
                .unwrap()
                .into();
            assert!(authenticate_withdrawal_intent(reopened, &a).is_err());
            let mut intent = WithdrawalIntent {
                protocol: "auto-config-withdrawal-v1".into(),
                target: f.path(),
                parent: identity(&stat(target.parent.as_raw_fd()).unwrap()),
                retired_name: random_name().to_str().unwrap().into(),
                root: own.intent.new_root.clone(),
                current: GenerationWire {
                    entries: own.current.entries.clone(),
                },
                publication_epoch: "invalid".into(),
            };
            assert!(classify_withdrawal(&target, &intent).is_err());
            intent.publication_epoch = own.intent.epoch.clone();
            intent.root.ino += 1;
            assert!(classify_withdrawal(&target, &intent).is_err());
        }
        #[test]
        fn interrupted_retirement_reopens_durable_own_receipt() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let target = Target::open(&f.path()).unwrap();
            let retired = restore_original_absence(&target, &r, |_| Ok(())).unwrap();
            let (stage, a) = stage_record(
                &f,
                |b| retired.durable_bytes(b).unwrap(),
                "withdrawal-receipt.json",
            );
            let authenticated = authenticate_record(stage, "withdrawal-receipt.json", &a).unwrap();
            let reopened = reopen_withdrawal_receipt(&target, &authenticated).unwrap();
            revalidate_withdrawal(&target, &reopened).unwrap();
        }
        #[test]
        fn hostile_replacement_blocks_absence_rollback() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let target = Target::open(&f.path()).unwrap();
            std::fs::rename(f.path(), f.base.join("kept")).unwrap();
            let victim = f.base.join("victim");
            std::fs::create_dir(&victim).unwrap();
            std::fs::write(victim.join("proof"), b"victim").unwrap();
            symlink(&victim, f.path()).unwrap();
            assert!(restore_original_absence(&target, &r, |_| Ok(())).is_err());
            assert_eq!(std::fs::read(victim.join("proof")).unwrap(), b"victim");
        }
        #[test]
        fn sticky_tmp_is_only_ancestor_not_final_parent() {
            assert!(Target::open(Path::new("/tmp/config")).is_err());
            let f = Private::new();
            Target::open(&f.path()).unwrap();
        }
        struct ExpectedCapture {
            path: PathBuf,
            witness: Option<Vec<u8>>,
        }
        impl CaptureGuard for ExpectedCapture {
            fn validate_captured_generation(&self, p: &Path, g: Option<&Generation>) -> Result<()> {
                if p == self.path && g.map(|x| x.witness()).transpose()? == self.witness {
                    Ok(())
                } else {
                    Err("capture witness mismatch")
                }
            }
        }
        fn runtime_state_version(
            f: &Private,
            bytes: &[u8],
            uid: u32,
            gid: u32,
        ) -> PublicationReceipt {
            let target = Target::open(&f.path()).unwrap();
            let expected = target.inspect().unwrap();
            if let Some(old) = &expected {
                admit_supported_original_runtime_state(old).unwrap();
            }
            let guard = ExpectedCapture {
                path: f.path(),
                witness: expected.as_ref().map(|g| g.witness().unwrap()),
            };
            Prepared::build_policy_captured(
                target,
                expected,
                &Private::tree(bytes),
                uid,
                gid,
                RootMode::RuntimeState0700,
                |_| Ok(()),
                &guard,
            )
            .unwrap()
            .publish_captured(|_| Ok(()), &guard)
            .unwrap()
        }
        #[test]
        fn retained_predecessor_binds_actual_original_and_retired_new_inodes() {
            let f = Private::new();
            let (uid, gid) = f.ids();
            runtime_state_version(&f, b"original", uid, gid);
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
            std::fs::set_permissions(
                f.path().join("a.conf"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            let forward = runtime_state_version(&f, b"replacement", uid, gid);
            let guard = ExpectedCapture {
                path: f.path(),
                witness: Some(forward.generation().witness().unwrap()),
            };
            let restored = restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &forward,
                |_| Ok(()),
                &guard,
            )
            .unwrap();
            validate_retained_restore_predecessor(&forward, &restored).unwrap();
            assert!(validate_retained_restore_predecessor(&restored, &forward).is_err());
            assert!(validate_retained_restore_predecessor(&forward, &forward).is_err());
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"original");
            assert_eq!(
                std::fs::read(f.base.join(&forward.intent.stage).join("a.conf")).unwrap(),
                b"replacement"
            );
            // Actual post-restore mutation invalidates the original generation.
            std::fs::write(f.path().join("a.conf"), b"changed original").unwrap();
            assert!(validate_retained_restore_predecessor(&forward, &restored).is_err());
        }
        #[test]
        fn retained_predecessor_refuses_other_forward_epoch_at_same_target() {
            let f = Private::new();
            let (uid, gid) = f.ids();
            runtime_state_version(&f, b"original", uid, gid);
            let prior = runtime_state_version(&f, b"middle", uid, gid);
            let forward = runtime_state_version(&f, b"replacement", uid, gid);
            let guard = ExpectedCapture {
                path: f.path(),
                witness: Some(forward.generation().witness().unwrap()),
            };
            let restored = restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &forward,
                |_| Ok(()),
                &guard,
            )
            .unwrap();
            validate_retained_restore_predecessor(&forward, &restored).unwrap();
            assert!(validate_retained_restore_predecessor(&prior, &restored).is_err());
        }
        #[test]
        fn withdrawal_predecessor_checks_true_absence_and_retained_new_tree() {
            let f = Private::new();
            let (uid, gid) = f.ids();
            let forward = runtime_state_version(&f, b"new", uid, gid);
            let target = Target::open(&f.path()).unwrap();
            let withdrawn = restore_original_absence(&target, &forward, |_| Ok(())).unwrap();
            validate_withdrawal_predecessor(&forward, &withdrawn).unwrap();
            assert!(!f.path().exists());
            assert_eq!(
                std::fs::read(f.base.join(withdrawn.retained_name()).join("a.conf")).unwrap(),
                b"new"
            );
            std::fs::create_dir(f.path()).unwrap();
            assert!(validate_withdrawal_predecessor(&forward, &withdrawn).is_err());
        }
        #[test]
        fn withdrawal_predecessor_accepts_authenticated_earlier_absence_chain_not_direct_old_flag()
        {
            struct ActualHistory<'a> {
                first: &'a PublicationReceipt,
                current: &'a PublicationReceipt,
            }
            impl OwnAbsenceChainAuthority for ActualHistory<'_> {
                fn validate_original_absence_and_chain(
                    &self,
                    path: &Path,
                    epoch: &str,
                ) -> Result<()> {
                    let old = Generation {
                        entries: self
                            .current
                            .intent
                            .old
                            .as_ref()
                            .ok_or(REFUSED)?
                            .entries
                            .clone(),
                    };
                    if self.first.intent.old.is_some()
                        || path != self.first.intent.target
                        || path != self.current.intent.target
                        || epoch != self.current.intent.epoch
                        || self.first.intent.parent != self.current.intent.parent
                        || !same_displaced(Some(&old), Some(&self.first.current))
                    {
                        return Err(REFUSED);
                    }
                    revalidate_predecessor_tree(&self.first.root, &self.first.current)
                }
            }
            let f = Private::new();
            let (uid, gid) = f.ids();
            let first = runtime_state_version(&f, b"first owned", uid, gid);
            let forward = runtime_state_version(&f, b"second owned", uid, gid);
            assert!(forward.intent.old.is_some());
            let target = Target::open(&f.path()).unwrap();
            let proof = ActualHistory {
                first: &first,
                current: &forward,
            };
            let withdrawn =
                restore_original_absence_after_own_chain(&target, &forward, &proof, |_| Ok(()))
                    .unwrap();
            validate_withdrawal_predecessor(&forward, &withdrawn).unwrap();
            assert!(validate_withdrawal_predecessor(&first, &withdrawn).is_err());
            assert!(!f.path().exists());
            assert_eq!(
                std::fs::read(f.base.join(withdrawn.retained_name()).join("a.conf")).unwrap(),
                b"second owned"
            );
        }
        #[test]
        fn retained_runtime_state_restore_preserves_original_inode_bytes_modes_and_empty_dirs() {
            use std::os::unix::fs::MetadataExt;
            let f = Private::new();
            let (uid, gid) = f.ids();
            runtime_state_version(&f, b"original", uid, gid);
            let original = std::fs::metadata(f.path()).unwrap();
            let old_leaf = std::fs::metadata(f.path().join("a.conf")).unwrap();
            let current = runtime_state_version(&f, b"replacement", uid, gid);
            let guard = ExpectedCapture {
                path: f.path(),
                witness: Some(current.generation().witness().unwrap()),
            };
            let restored = restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &current,
                |_| Ok(()),
                &guard,
            )
            .unwrap();
            let now = std::fs::metadata(f.path()).unwrap();
            let leaf = std::fs::metadata(f.path().join("a.conf")).unwrap();
            assert_eq!(
                (now.dev(), now.ino(), now.uid(), now.gid(), now.mode()),
                (
                    original.dev(),
                    original.ino(),
                    original.uid(),
                    original.gid(),
                    original.mode()
                )
            );
            assert_eq!(
                (leaf.dev(), leaf.ino(), leaf.uid(), leaf.gid(), leaf.mode()),
                (
                    old_leaf.dev(),
                    old_leaf.ino(),
                    old_leaf.uid(),
                    old_leaf.gid(),
                    old_leaf.mode()
                )
            );
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"original");
            assert!(f.path().join("empty/child").is_dir());
            revalidate_current_receipt(&Target::open(&f.path()).unwrap(), &restored).unwrap();
            assert_eq!(
                std::fs::read(f.base.join(&restored.intent.stage).join("a.conf")).unwrap(),
                b"replacement"
            );
        }
        #[test]
        fn heterogeneous_original_modes_restore_reopen_and_pending_recovery_exactly() {
            use std::os::unix::fs::MetadataExt;
            let f = Private::new();
            let (uid, gid) = f.ids();
            runtime_state_version(&f, b"original", uid, gid);
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
            std::fs::set_permissions(
                f.path().join("a.conf"),
                std::fs::Permissions::from_mode(0o640),
            )
            .unwrap();
            std::fs::set_permissions(
                f.path().join("nested/b.conf"),
                std::fs::Permissions::from_mode(0o400),
            )
            .unwrap();
            let old_root = std::fs::metadata(f.path()).unwrap();
            let old_first = std::fs::metadata(f.path().join("a.conf")).unwrap();
            let current = runtime_state_version(&f, b"replacement", uid, gid);
            let guard = ExpectedCapture {
                path: f.path(),
                witness: Some(current.generation().witness().unwrap()),
            };
            let mut durable = None;
            let restored = restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &current,
                |intent| {
                    durable = Some(pending_intent_record(&f, intent));
                    Ok(())
                },
                &guard,
            )
            .unwrap();
            let (stage, authority) = durable.unwrap();
            let authenticated = authenticate_intent(stage, &authority).unwrap();
            let recovered = recover_own_receipt(&Target::open(&f.path()).unwrap(), &authenticated)
                .unwrap()
                .unwrap();
            let now = std::fs::metadata(f.path()).unwrap();
            let first = std::fs::metadata(f.path().join("a.conf")).unwrap();
            assert_eq!(
                (now.dev(), now.ino(), now.uid(), now.gid(), now.mode()),
                (
                    old_root.dev(),
                    old_root.ino(),
                    old_root.uid(),
                    old_root.gid(),
                    old_root.mode()
                )
            );
            assert_eq!(
                (
                    first.dev(),
                    first.ino(),
                    first.uid(),
                    first.gid(),
                    first.mode()
                ),
                (
                    old_first.dev(),
                    old_first.ino(),
                    old_first.uid(),
                    old_first.gid(),
                    old_first.mode()
                )
            );
            assert_eq!(
                std::fs::metadata(f.path().join("nested/b.conf"))
                    .unwrap()
                    .mode()
                    & 0o7777,
                0o400
            );
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"original");
            assert!(f.path().join("empty/child").is_dir());
            let (stage, authority) = stage_record(
                &f,
                |b| restored.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            let record =
                authenticate_record(stage, "publication-receipt.json", &authority).unwrap();
            let reopened = reopen_own_receipt(&Target::open(&f.path()).unwrap(), &record).unwrap();
            assert_eq!(reopened.generation(), recovered.generation());
            assert!(verify_runtime_state_policy(
                &Target::open(&f.path()).unwrap(),
                &reopened,
                uid,
                gid
            )
            .is_err());
        }
        #[test]
        fn retained_policy_cannot_build_new_state_or_repair_original_permissions() {
            let f = Private::new();
            let (uid, gid) = f.ids();
            assert!(Prepared::build_policy(
                Target::open(&f.path()).unwrap(),
                None,
                &Private::tree(b"new"),
                uid,
                gid,
                RootMode::RetainedOriginalTree,
                |_| Ok(())
            )
            .is_err());
            assert!(!f.path().exists());
        }
        #[test]
        #[ignore = "explicit privileged Linux heterogeneous-owner fixture; not ordinary CI acceptance"]
        fn retained_heterogeneous_owners_and_groups_are_not_flattened() {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let f = Private::new();
            runtime_state_version(&f, b"original", 0, 0);
            let leaf = f.path().join("a.conf");
            let c_path = std::ffi::CString::new(leaf.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::chown(c_path.as_ptr(), 65534, 1) }, 0);
            std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o640)).unwrap();
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
            let before = std::fs::metadata(&leaf).unwrap();
            let current = runtime_state_version(&f, b"replacement", 65534, 65534);
            let guard = ExpectedCapture {
                path: f.path(),
                witness: Some(current.generation().witness().unwrap()),
            };
            restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &current,
                |_| Ok(()),
                &guard,
            )
            .unwrap();
            let after = std::fs::metadata(&leaf).unwrap();
            assert_eq!(
                (
                    after.dev(),
                    after.ino(),
                    after.uid(),
                    after.gid(),
                    after.mode()
                ),
                (
                    before.dev(),
                    before.ino(),
                    before.uid(),
                    before.gid(),
                    before.mode()
                )
            );
            assert_eq!(std::fs::metadata(f.path()).unwrap().mode() & 0o7777, 0o750);
            assert_eq!(std::fs::read(leaf).unwrap(), b"original");
        }
        #[test]
        fn retained_state_epoch_refusal_after_intent_leaves_both_generations_unchanged() {
            struct Admission {
                expected: ExpectedCapture,
                refused: std::cell::Cell<bool>,
            }
            impl CaptureGuard for Admission {
                fn validate_captured_generation(
                    &self,
                    p: &Path,
                    g: Option<&Generation>,
                ) -> Result<()> {
                    if self.refused.get() {
                        return Err("changed stopped-unit epoch");
                    }
                    self.expected.validate_captured_generation(p, g)
                }
            }
            let f = Private::new();
            let (uid, gid) = f.ids();
            runtime_state_version(&f, b"original", uid, gid);
            let current = runtime_state_version(&f, b"replacement", uid, gid);
            let admission = Admission {
                expected: ExpectedCapture {
                    path: f.path(),
                    witness: Some(current.generation().witness().unwrap()),
                },
                refused: std::cell::Cell::new(false),
            };
            let mut durable = None;
            assert!(restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &current,
                |intent| {
                    durable = Some(pending_intent_record(&f, intent));
                    admission.refused.set(true);
                    Ok(())
                },
                &admission
            )
            .is_err());
            let (stage, authority) = durable.unwrap();
            let pending = authenticate_intent(stage, &authority).unwrap();
            assert!(
                recover_own_receipt(&Target::open(&f.path()).unwrap(), &pending)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                std::fs::read(f.path().join("a.conf")).unwrap(),
                b"replacement"
            );
            assert_eq!(
                std::fs::read(f.base.join(&current.intent.stage).join("a.conf")).unwrap(),
                b"original"
            );
        }
        #[test]
        fn unsafe_original_state_mode_refuses_before_replacement_or_permission_repair() {
            use std::os::unix::fs::MetadataExt;
            let f = Private::new();
            let (uid, gid) = f.ids();
            runtime_state_version(&f, b"original", uid, gid);
            std::fs::set_permissions(
                f.path().join("a.conf"),
                std::fs::Permissions::from_mode(0o620),
            )
            .unwrap();
            let before = std::fs::metadata(f.path()).unwrap();
            let original = Target::open(&f.path()).unwrap().inspect().unwrap().unwrap();
            assert!(admit_supported_original_runtime_state(&original).is_err());
            let after = std::fs::metadata(f.path()).unwrap();
            assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
            assert_eq!(
                std::fs::metadata(f.path().join("a.conf")).unwrap().mode() & 0o7777,
                0o620
            );
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"original");
        }
        #[test]
        #[ignore = "explicit privileged Linux state UID transition fixture; not ordinary CI acceptance"]
        fn privileged_retained_state_restores_old_uid_and_inode_without_chown() {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(unsafe { libc::geteuid() }, 0);
            let f = Private::new();
            runtime_state_version(&f, b"original", 0, 0);
            let original = std::fs::metadata(f.path()).unwrap();
            let current = runtime_state_version(&f, b"replacement", 65534, 65534);
            assert_eq!(std::fs::metadata(f.path()).unwrap().uid(), 65534);
            let guard = ExpectedCapture {
                path: f.path(),
                witness: Some(current.generation().witness().unwrap()),
            };
            restore_retained_original_tree(
                Target::open(&f.path()).unwrap(),
                &current,
                |_| Ok(()),
                &guard,
            )
            .unwrap();
            let restored = std::fs::metadata(f.path()).unwrap();
            assert_eq!(
                (
                    restored.dev(),
                    restored.ino(),
                    restored.uid(),
                    restored.gid()
                ),
                (original.dev(), original.ino(), 0, 0)
            );
            assert_eq!(std::fs::read(f.path().join("a.conf")).unwrap(), b"original");
        }
        #[test]
        fn capture_guard_rechecked_after_durable_intent() {
            let f = Private::new();
            let t = Target::open(&f.path()).unwrap();
            let expected = t.inspect().unwrap();
            let g = ExpectedCapture {
                path: f.path(),
                witness: expected.as_ref().map(|x| x.witness().unwrap()),
            };
            let (uid, gid) = f.ids();
            let p = Prepared::build_captured(
                t,
                expected,
                &Private::tree(b"captured"),
                uid,
                gid,
                |_| Ok(()),
                &g,
            )
            .unwrap();
            assert!(p
                .publish_captured(
                    |_| {
                        std::fs::create_dir(f.path()).unwrap();
                        std::fs::write(f.path().join("foreign"), b"foreign").unwrap();
                        Ok(())
                    },
                    &g
                )
                .is_err());
            assert_eq!(std::fs::read(f.path().join("foreign")).unwrap(), b"foreign");
        }

        fn pending_intent_record(
            f: &Private,
            intent: &PublicationIntent,
        ) -> (OwnedFd, TestAuthority) {
            let stage = f.base.join("pending-store");
            std::fs::create_dir(&stage).unwrap();
            std::fs::set_permissions(&stage, std::fs::Permissions::from_mode(0o700)).unwrap();
            let stage_fd: OwnedFd = File::open(&stage).unwrap().into();
            let stage_id = identity(&stat(stage_fd.as_raw_fd()).unwrap());
            let binding = RecordBinding {
                transaction_stage: stage_id.clone(),
                transaction_nonce: "123456789012345678901234567890ab".into(),
                phase: "prepared".into(),
                chain_sha256: "b".repeat(64),
            };
            let bytes = intent.durable_bytes(binding.clone()).unwrap();
            let hash = format!("{:x}", Sha256::digest(&bytes));
            std::fs::write(stage.join("publication-intent.json"), bytes).unwrap();
            std::fs::set_permissions(
                stage.join("publication-intent.json"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            (
                stage_fd,
                TestAuthority {
                    stage: stage_id,
                    phase: binding.phase,
                    hash,
                    nonce: binding.transaction_nonce,
                    chain: binding.chain_sha256,
                },
            )
        }
        // The worker is isolated in an owned child: a regression in openat
        // flags must fail within a deadline rather than hang the test runner.
        #[test]
        #[ignore = "only invoked by the bounded parent test"]
        fn private_fifo_record_refusal_worker() {
            assert_eq!(
                std::env::var_os("AEGIS_PRIVATE_FIFO_REFUSAL_WORKER"),
                Some(std::ffi::OsString::from("1")),
                "FIFO worker must be invoked by its bounded parent"
            );
            let f = Private::new();
            let prepared = f.prepare(&Private::tree(b"captured"));
            let intent = prepared.intent().unwrap();
            let (stage, authority) = pending_intent_record(&f, &intent);
            let authenticated = authenticate_intent(stage, &authority).unwrap();
            let stage_path = f.base.join("pending-store");
            let leaf = stage_path.join("publication-intent.json");
            std::fs::rename(&leaf, stage_path.join("preserved-intent.json")).unwrap();
            let fifo_name = c(leaf.as_os_str()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
            std::fs::set_permissions(&leaf, std::fs::Permissions::from_mode(0o600)).unwrap();
            // Exercise both a previously authenticated pending intent and fresh
            // admission; no writer opens the FIFO, so blocking open is causal.
            assert!(authenticated.recheck_stage().is_err());
            let fresh: OwnedFd = File::open(&stage_path).unwrap().into();
            assert!(authenticate_intent(fresh, &authority).is_err());
            std::fs::rename(&leaf, stage_path.join("publication-receipt.json")).unwrap();
            let fresh: OwnedFd = File::open(&stage_path).unwrap().into();
            assert!(authenticate_record(fresh, "publication-receipt.json", &authority).is_err());
            assert!(stage_path.join("preserved-intent.json").is_file());
        }
        #[test]
        fn private_fifo_record_refusal_is_bounded() {
            use std::process::{Command, Stdio};
            use std::time::{Duration, Instant};
            let mut child = Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("profile_auto_publication::linux::tests::private_fifo_record_refusal_worker")
                .arg("--ignored")
                .arg("--nocapture")
                .env("AEGIS_PRIVATE_FIFO_REFUSAL_WORKER", "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(status) = child.try_wait().unwrap() {
                    assert!(status.success(), "FIFO refusal worker failed");
                    break;
                }
                if Instant::now() >= deadline {
                    // Only the still-owned, unreaped Child is terminated; no
                    // arbitrary PID, shell command or process-wide signal.
                    let _ = child.kill();
                    let reap_deadline = Instant::now() + Duration::from_secs(2);
                    while child.try_wait().unwrap().is_none() && Instant::now() < reap_deadline {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    panic!("private FIFO admission blocked beyond its deadline");
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        #[test]
        fn pending_intent_crash_before_rename_returns_none_and_retains_stage() {
            let f = Private::new();
            let p = f.prepare(&Private::tree(b"captured-new"));
            let intent = p.intent().unwrap();
            let (stage, authority) = pending_intent_record(&f, &intent);
            drop(p);
            let admitted = authenticate_intent(stage, &authority).unwrap();
            let target = Target::open(&f.path()).unwrap();
            assert!(recover_own_receipt(&target, &admitted).unwrap().is_none());
            assert!(!f.path().exists());
            assert_eq!(
                std::fs::read(f.base.join(&intent.stage).join("a.conf")).unwrap(),
                b"captured-new"
            );
        }
        #[test]
        fn pending_intent_crash_after_exchange_recovers_actual_own_receipt() {
            let f = Private::new();
            f.prepare(&Private::tree(b"old"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let p = f.prepare(&Private::tree(b"captured-new"));
            let intent = p.intent().unwrap();
            let (stage, authority) = pending_intent_record(&f, &intent);
            // Exercise the actual interrupted syscall boundary without the ordinary
            // publish continuation; original bytes are never loaded during recover.
            rename(
                p.target.parent.as_raw_fd(),
                &p.stage,
                &p.target.leaf,
                libc::RENAME_EXCHANGE,
            )
            .unwrap();
            sync(p.target.parent.as_raw_fd()).unwrap();
            drop(p);
            let admitted = authenticate_intent(stage, &authority).unwrap();
            let target = Target::open(&f.path()).unwrap();
            let receipt = recover_own_receipt(&target, &admitted).unwrap().unwrap();
            revalidate_current_receipt(&target, &receipt).unwrap();
            assert_eq!(
                std::fs::read(f.path().join("a.conf")).unwrap(),
                b"captured-new"
            );
            assert_eq!(
                std::fs::read(f.base.join(&intent.stage).join("a.conf")).unwrap(),
                b"old"
            );
            assert_eq!(
                std::fs::metadata(f.path()).unwrap().permissions().mode() & 0o777,
                0o750
            );
        }
        #[test]
        fn pending_intent_wrong_phase_or_hash_cannot_recover() {
            let f = Private::new();
            let p = f.prepare(&Private::tree(b"new"));
            let intent = p.intent().unwrap();
            let (stage, mut authority) = pending_intent_record(&f, &intent);
            authority.hash = "0".repeat(64);
            assert!(authenticate_intent(stage, &authority).is_err());
            assert!(!f.path().exists());
        }
        #[test]
        fn pending_intent_stage_file_symlink_refuses_without_victim_read_or_write() {
            let f = Private::new();
            let p = f.prepare(&Private::tree(b"new"));
            let intent = p.intent().unwrap();
            let (stage, authority) = pending_intent_record(&f, &intent);
            let record = f.base.join("pending-store/publication-intent.json");
            std::fs::remove_file(&record).unwrap();
            let victim = f.base.join("victim");
            std::fs::write(&victim, b"unrelated").unwrap();
            symlink(&victim, &record).unwrap();
            assert!(authenticate_intent(stage, &authority).is_err());
            assert_eq!(std::fs::read(victim).unwrap(), b"unrelated");
        }
        #[test]
        fn pending_intent_new_target_substitution_refuses_and_preserves_victim() {
            let f = Private::new();
            let p = f.prepare(&Private::tree(b"new"));
            let intent = p.intent().unwrap();
            let (stage, authority) = pending_intent_record(&f, &intent);
            rename(
                p.target.parent.as_raw_fd(),
                &p.stage,
                &p.target.leaf,
                libc::RENAME_NOREPLACE,
            )
            .unwrap();
            drop(p);
            let admitted = authenticate_intent(stage, &authority).unwrap();
            std::fs::rename(f.path(), f.base.join("kept-new")).unwrap();
            let victim = f.base.join("victim");
            std::fs::create_dir(&victim).unwrap();
            std::fs::write(victim.join("proof"), b"unrelated").unwrap();
            symlink(&victim, f.path()).unwrap();
            assert!(recover_own_receipt(&Target::open(&f.path()).unwrap(), &admitted).is_err());
            assert_eq!(std::fs::read(victim.join("proof")).unwrap(), b"unrelated");
        }
        #[test]
        fn pending_intent_old_backup_substitution_blocks_recovery() {
            let f = Private::new();
            f.prepare(&Private::tree(b"old"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let p = f.prepare(&Private::tree(b"new"));
            let intent = p.intent().unwrap();
            let (stage, authority) = pending_intent_record(&f, &intent);
            rename(
                p.target.parent.as_raw_fd(),
                &p.stage,
                &p.target.leaf,
                libc::RENAME_EXCHANGE,
            )
            .unwrap();
            drop(p);
            let admitted = authenticate_intent(stage, &authority).unwrap();
            std::fs::rename(f.base.join(&intent.stage), f.base.join("kept-old")).unwrap();
            std::fs::create_dir(f.base.join(&intent.stage)).unwrap();
            std::fs::write(f.base.join(&intent.stage).join("victim"), b"unrelated").unwrap();
            assert!(recover_own_receipt(&Target::open(&f.path()).unwrap(), &admitted).is_err());
            assert_eq!(
                std::fs::read(f.base.join(&intent.stage).join("victim")).unwrap(),
                b"unrelated"
            );
        }

        #[test]
        fn pending_intent_after_new_root_chown_before_chmod_recovers() {
            let f = Private::new();
            let p = f.prepare(&Private::tree(b"new"));
            let intent = p.intent().unwrap();
            let (stage, authority) = pending_intent_record(&f, &intent);
            rename(
                p.target.parent.as_raw_fd(),
                &p.stage,
                &p.target.leaf,
                libc::RENAME_NOREPLACE,
            )
            .unwrap();
            assert_eq!(
                unsafe { libc::fchown(p.root.as_raw_fd(), intent.service_uid, intent.service_gid) },
                0
            );
            drop(p);
            let admitted = authenticate_intent(stage, &authority).unwrap();
            let target = Target::open(&f.path()).unwrap();
            let receipt = recover_own_receipt(&target, &admitted).unwrap().unwrap();
            revalidate_current_receipt(&target, &receipt).unwrap();
            assert_eq!(
                std::fs::metadata(f.path()).unwrap().permissions().mode() & 0o777,
                0o750
            );
        }

        #[test]
        fn published_view_reads_held_own_bytes_and_rejects_leaf_replacement() {
            let f = Private::new();
            let r = f
                .prepare(&Private::tree(b"actual-owned"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let t = Target::open(&f.path()).unwrap();
            assert_eq!(
                read_current_leaf(&t, &r, Path::new("a.conf"))
                    .unwrap()
                    .as_slice(),
                b"actual-owned"
            );
            assert_eq!(
                current_leaf_names(&t, &r).unwrap(),
                BTreeSet::from([PathBuf::from("a.conf"), PathBuf::from("nested/b.conf")])
            );
            std::fs::remove_file(f.path().join("a.conf")).unwrap();
            let victim = f.base.join("victim");
            std::fs::write(&victim, b"victim").unwrap();
            symlink(&victim, f.path().join("a.conf")).unwrap();
            assert!(read_current_leaf(&t, &r, Path::new("a.conf")).is_err());
            assert_eq!(std::fs::read(victim).unwrap(), b"victim");
        }
        struct ExactAbsenceChain {
            target: PathBuf,
            epoch: String,
        }
        impl OwnAbsenceChainAuthority for ExactAbsenceChain {
            fn validate_original_absence_and_chain(&self, t: &Path, e: &str) -> Result<()> {
                if t == self.target && e == self.epoch {
                    Ok(())
                } else {
                    Err("test owned chain mismatch")
                }
            }
        }
        #[test]
        fn authenticated_historical_withdrawal_pair_links_without_old_current_name() {
            let f = Private::new();
            f.prepare(&Private::tree(b"custody"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let current = f
                .prepare(&Private::tree(b"final"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            assert!(current.intent.old.is_some());
            let proof = ExactAbsenceChain {
                target: f.path(),
                epoch: current.intent.epoch.clone(),
            };
            let target = Target::open(&f.path()).unwrap();
            let retired =
                restore_original_absence_after_own_chain(&target, &current, &proof, |_| Ok(()))
                    .unwrap();
            let (fs, fa) = stage_record(
                &f,
                |binding| current.durable_bytes(binding).unwrap(),
                "publication-receipt.json",
            );
            let forward = authenticate_record(fs, "publication-receipt.json", &fa).unwrap();
            let (ws, wa) = withdrawal_stage_record(
                &f,
                |binding| retired.durable_bytes(binding).unwrap(),
                "withdrawal-receipt.json",
            );
            let withdrawn = authenticate_record(ws, "withdrawal-receipt.json", &wa).unwrap();
            assert!(!f.path().exists());
            validate_authenticated_withdrawal_predecessor(&forward, &withdrawn, &proof).unwrap();
            let live = reopen_withdrawal_receipt(&target, &withdrawn).unwrap();
            revalidate_withdrawal(&target, &live).unwrap();
            // Historical linkage stays valid after target appearance; it cannot
            // masquerade as actual live absence or authorize further mutation.
            std::fs::create_dir(f.path()).unwrap();
            validate_authenticated_withdrawal_predecessor(&forward, &withdrawn, &proof).unwrap();
            assert!(reopen_withdrawal_receipt(&target, &withdrawn).is_err());
            let wrong = ExactAbsenceChain {
                target: f.path(),
                epoch: "foreign".into(),
            };
            assert!(
                validate_authenticated_withdrawal_predecessor(&forward, &withdrawn, &wrong)
                    .is_err()
            );
            assert!(
                validate_authenticated_withdrawal_predecessor(&withdrawn, &forward, &proof)
                    .is_err()
            );
        }
        #[test]
        fn authenticated_historical_withdrawal_pair_refuses_changed_protected_bytes() {
            let f = Private::new();
            let current = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let proof = ExactAbsenceChain {
                target: f.path(),
                epoch: current.intent.epoch.clone(),
            };
            let retired = restore_original_absence_after_own_chain(
                &Target::open(&f.path()).unwrap(),
                &current,
                &proof,
                |_| Ok(()),
            )
            .unwrap();
            let (fs, fa) = stage_record(
                &f,
                |binding| current.durable_bytes(binding).unwrap(),
                "publication-receipt.json",
            );
            let forward = authenticate_record(fs, "publication-receipt.json", &fa).unwrap();
            let (ws, wa) = withdrawal_stage_record(
                &f,
                |binding| retired.durable_bytes(binding).unwrap(),
                "withdrawal-receipt.json",
            );
            let withdrawn = authenticate_record(ws, "withdrawal-receipt.json", &wa).unwrap();
            validate_authenticated_withdrawal_predecessor(&forward, &withdrawn, &proof).unwrap();
            std::fs::write(
                f.base
                    .join("store-withdrawal-receipt.json/withdrawal-receipt.json"),
                b"changed",
            )
            .unwrap();
            assert!(
                validate_authenticated_withdrawal_predecessor(&forward, &withdrawn, &proof)
                    .is_err()
            );
        }
        #[test]
        fn authenticated_historical_withdrawal_pair_refuses_foreign_transaction_nonce() {
            let f = Private::new();
            let current = f
                .prepare(&Private::tree(b"new"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let proof = ExactAbsenceChain {
                target: f.path(),
                epoch: current.intent.epoch.clone(),
            };
            let retired = restore_original_absence_after_own_chain(
                &Target::open(&f.path()).unwrap(),
                &current,
                &proof,
                |_| Ok(()),
            )
            .unwrap();
            let (fs, fa) = stage_record(
                &f,
                |binding| current.durable_bytes(binding).unwrap(),
                "publication-receipt.json",
            );
            let forward = authenticate_record(fs, "publication-receipt.json", &fa).unwrap();
            let nonce = "fedcba9876543210fedcba9876543210";
            let (ws, mut wa) = withdrawal_stage_record(
                &f,
                |mut binding| {
                    binding.transaction_nonce = nonce.into();
                    retired.durable_bytes(binding).unwrap()
                },
                "withdrawal-receipt.json",
            );
            wa.nonce = nonce.into();
            let withdrawn = authenticate_record(ws, "withdrawal-receipt.json", &wa).unwrap();
            assert!(
                validate_authenticated_withdrawal_predecessor(&forward, &withdrawn, &proof)
                    .is_err()
            );
        }
        #[test]
        fn absent_original_after_multiple_owned_epochs_uses_bound_chain() {
            let f = Private::new();
            f.prepare(&Private::tree(b"custody"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let current = f
                .prepare(&Private::tree(b"final"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let t = Target::open(&f.path()).unwrap();
            assert!(restore_original_absence(&t, &current, |_| Ok(())).is_err());
            let proof = ExactAbsenceChain {
                target: f.path(),
                epoch: current.intent.epoch.clone(),
            };
            let retired =
                restore_original_absence_after_own_chain(&t, &current, &proof, |_| Ok(())).unwrap();
            revalidate_withdrawal(&t, &retired).unwrap();
            assert!(!f.path().exists());
        }

        #[test]
        fn trusted_sgid_parent_service_publication_clears_only_new_special_bits() {
            let f = Private::new();
            std::fs::set_permissions(&f.base, std::fs::Permissions::from_mode(0o2700)).unwrap();
            let p = f.prepare(&Private::tree(b"new-under-sgid-parent"));
            let stage = p.intent().unwrap();
            assert_eq!(
                stat(p.root.as_raw_fd()).unwrap().st_mode & libc::S_ISGID,
                libc::S_ISGID
            );
            let receipt = p.publish(|_| Ok(()), |_, _| Ok(())).unwrap();
            let t = Target::open(&f.path()).unwrap();
            revalidate_current_receipt(&t, &receipt).unwrap();
            assert_eq!(
                std::fs::metadata(f.path()).unwrap().permissions().mode() & 0o7777,
                0o750
            );
            assert_eq!(
                std::fs::metadata(&f.base).unwrap().permissions().mode() & 0o7777,
                0o2700
            );
            assert_eq!(
                read_current_leaf(&t, &receipt, Path::new("a.conf"))
                    .unwrap()
                    .as_slice(),
                b"new-under-sgid-parent"
            );
            assert_eq!(stage.root_mode, RootMode::ServiceConfig0750);
        }
        #[test]
        fn exact_sgid_stage_intermediate_and_both_closed_final_policies() {
            // Real SGID directory descriptors witness the actual fchmod effect; no
            // root/sudo or false privileged admin publication test is performed.
            let f = Private::new();
            let sample = f.base.join("sample");
            std::fs::create_dir(&sample).unwrap();
            std::fs::set_permissions(&sample, std::fs::Permissions::from_mode(0o2700)).unwrap();
            let owned: OwnedFd = File::open(&sample).unwrap().into();
            let before = stat(owned.as_raw_fd()).unwrap();
            let original = Generation {
                entries: BTreeMap::from([(PathBuf::new(), metadata(&before))]),
            };
            let (uid, gid) = f.ids();
            assert_eq!(unsafe { libc::fchown(owned.as_raw_fd(), uid, gid) }, 0);
            let mut intermediate = original.clone();
            let top = intermediate.entries.get_mut(Path::new("")).unwrap();
            top.uid = uid;
            top.gid = gid;
            assert!(same_new_or_private(
                &intermediate,
                &original,
                uid,
                gid,
                RootMode::ServiceConfig0750
            ));
            for policy in [
                RootMode::ServiceConfig0750,
                RootMode::AdministratorMetadata0700,
            ] {
                assert_eq!(unsafe { libc::fchmod(owned.as_raw_fd(), policy.mode()) }, 0);
                let actual = Generation {
                    entries: BTreeMap::from([(
                        PathBuf::new(),
                        metadata(&stat(owned.as_raw_fd()).unwrap()),
                    )]),
                };
                assert!(same_new(&actual, &original, uid, gid, policy));
                assert_eq!(
                    stat(owned.as_raw_fd()).unwrap().st_mode & 0o7777,
                    policy.mode()
                );
            }
            // This validates BOTH closed semantic final policies against actual new
            // object FD modes, not privileged metadata role UID0/GID0 acceptance.
            let mut foreign = intermediate.clone();
            foreign.entries.get_mut(Path::new("")).unwrap().uid = uid.wrapping_add(1);
            assert!(!same_new_or_private(
                &foreign,
                &original,
                uid,
                gid,
                RootMode::ServiceConfig0750
            ));
        }

        struct ExactProjectionAdmission {
            target: PathBuf,
            hash: String,
            epoch: String,
            root: Identity,
        }
        impl ProjectionAdmission for ExactProjectionAdmission {
            fn admit_projection_source(&self, s: &ProjectionSource) -> Result<()> {
                if s.target == self.target
                    && s.base_record_sha256 == self.hash
                    && s.epoch == self.epoch
                    && s.root == self.root
                {
                    Ok(())
                } else {
                    Err("test projection admission mismatch")
                }
            }
        }
        fn projected_fixture(
            f: &Private,
        ) -> (AuthenticatedRecord, ExactProjectionAdmission, Vec<u8>) {
            let original=b"mode = 'relay'\n[relay]\nserver = '203.0.113.7:443'\nauth_token = 'synthetic-token'\n[ingress.wide]\ndns_preview_listen = '127.0.0.1:53'\ndns_preview_fake_ip_pool = '198.18.0.0/15'\ndns_preview_fake_ip_ttl_secs = 60\n".to_vec();
            let tree = CapturedTree::new(
                BTreeMap::from([
                    (PathBuf::from("aegis.toml"), original.clone()),
                    (PathBuf::from("other.conf"), b"unchanged".to_vec()),
                ]),
                BTreeSet::new(),
            )
            .unwrap();
            let r = f.prepare(&tree).publish(|_| Ok(()), |_, _| Ok(())).unwrap();
            let (stage, a) = stage_record(
                f,
                |b| r.durable_bytes(b).unwrap(),
                "publication-receipt.json",
            );
            let record = authenticate_record(stage, "publication-receipt.json", &a).unwrap();
            let authority = ExactProjectionAdmission {
                target: f.path(),
                hash: record.record_hash().into(),
                epoch: r.intent.epoch.clone(),
                root: r.intent.new_root.clone(),
            };
            (record, authority, original)
        }
        #[test]
        fn actual_formatter_snapshot_accepts_only_exact_toml_semantics_and_main_scope() {
            let f = Private::new();
            let (record, authority, original) = projected_fixture(&f);
            let value: toml::Value =
                toml::from_str(std::str::from_utf8(&original).unwrap()).unwrap();
            let formatted = toml::to_string_pretty(&value).unwrap();
            assert_ne!(formatted.as_bytes(), original.as_slice());
            std::fs::write(f.path().join("aegis.toml"), &formatted).unwrap();
            let target = Target::open(&f.path()).unwrap();
            let view = ProjectionView::admit(&target, &record, &authority).unwrap();
            assert_eq!(
                toml::from_str::<toml::Value>(std::str::from_utf8(view.main_bytes()).unwrap())
                    .unwrap(),
                value
            );
            assert_eq!(
                view.read_leaf(&target, Path::new("other.conf"))
                    .unwrap()
                    .as_slice(),
                b"unchanged"
            );
            view.revalidate(&target, &authority).unwrap();
        }
        #[test]
        fn formatter_changed_unrelated_file_or_membership_refuses() {
            let f = Private::new();
            let (record, authority, _) = projected_fixture(&f);
            std::fs::write(f.path().join("other.conf"), b"changed").unwrap();
            assert!(
                ProjectionView::admit(&Target::open(&f.path()).unwrap(), &record, &authority)
                    .is_err()
            );
            let fresh = Private::new();
            let (record, authority, _) = projected_fixture(&fresh);
            std::fs::write(fresh.path().join("unexpected.conf"), b"new-member").unwrap();
            assert!(ProjectionView::admit(
                &Target::open(&fresh.path()).unwrap(),
                &record,
                &authority
            )
            .is_err());
        }
        #[test]
        fn formatter_main_symlink_or_foreign_mode_refuses_victim_untouched() {
            let f = Private::new();
            let (record, authority, _) = projected_fixture(&f);
            std::fs::set_permissions(
                f.path().join("aegis.toml"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(
                ProjectionView::admit(&Target::open(&f.path()).unwrap(), &record, &authority)
                    .is_err()
            );
            std::fs::remove_file(f.path().join("aegis.toml")).unwrap();
            let victim = f.base.join("victim");
            std::fs::write(&victim, b"untouched").unwrap();
            symlink(&victim, f.path().join("aegis.toml")).unwrap();
            assert!(
                ProjectionView::admit(&Target::open(&f.path()).unwrap(), &record, &authority)
                    .is_err()
            );
            assert_eq!(std::fs::read(victim).unwrap(), b"untouched");
        }
        #[test]
        fn formatter_unknown_toml_change_has_no_semantic_proof() {
            let f = Private::new();
            let (record, authority, original) = projected_fixture(&f);
            let mut altered = original.clone();
            altered.extend_from_slice(b"unknown_new_value = 'forbidden'\n");
            std::fs::write(f.path().join("aegis.toml"), &altered).unwrap();
            let target = Target::open(&f.path()).unwrap();
            let view = ProjectionView::admit(&target, &record, &authority).unwrap();
            let expected: toml::Value =
                toml::from_str(std::str::from_utf8(&original).unwrap()).unwrap();
            let actual: toml::Value =
                toml::from_str(std::str::from_utf8(view.main_bytes()).unwrap()).unwrap();
            assert_ne!(actual, expected); // No runtime VerifiedProjection can be constructed here.
            assert_eq!(
                view.read_leaf(&target, Path::new("other.conf"))
                    .unwrap()
                    .as_slice(),
                b"unchanged"
            );
        }
        #[test]
        fn counted_generation_and_digest_bind_actual_file_metadata() {
            let f = Private::new();
            f.prepare(&Private::tree(b"old"))
                .publish(|_| Ok(()), |_, _| Ok(()))
                .unwrap();
            let target = Target::open(&f.path()).unwrap();
            let before = target.inspect().unwrap().unwrap();
            assert_eq!(before.entry_count(), 6); // root, three dirs, two files
            let first_digest = before.digest().unwrap();
            std::fs::write(f.path().join("a.conf"), b"changed-longer").unwrap();
            let after = target.inspect().unwrap().unwrap();
            assert_eq!(after.entry_count(), before.entry_count());
            assert_ne!(after.digest().unwrap(), first_digest);
        }
    }
}
