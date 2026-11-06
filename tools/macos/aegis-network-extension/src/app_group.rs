//! Native read-only custody. OS signing/entitlement/container admission is not
//! enrollment, PKI acceptance, permission ACK, or an engine factory.
use crate::identity_custody::{self, HeldIdentityBytes, HeldIssuance};
use crate::identity_import::{TreeLease, PROVIDER_TREE_GATE};
use aegis_client::online_expectation::OnlineExpectation;
use aegis_client::public_profile_file::{profile_digest_bytes, MAX_PUBLIC_BYTES, MEMBERS};
use aegis_core::https_bridge::{ClientSettings as BridgeSettings, SIDECAR};
use aegis_core::web_response_profile::WebResponseSettings;
use objc2::{class, msg_send, rc::Retained, runtime::AnyObject};
use objc2_foundation::NSString;
use std::{
    ffi::{c_void, CString},
    fs::File,
    io::{self, Read, Seek, SeekFrom, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Component, Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;
const MAX_FILE: u64 = 1024 * 1024;
const MAX_RUNTIME_FILE: u64 = 4096;
static RUNTIME_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);
pub(crate) const PROVIDER_BUNDLE_ID: &str = "dev.aegis.macos.PacketTunnel";
pub(crate) const HOST_BUNDLE_ID: &str = "dev.aegis.macos";
const OBSERVATION_CHILD_BUNDLE_ID: &str = "dev.aegis.macos.ObserveChild";
const PROVIDER_NE_ENTITLEMENT: &str = "packet-tunnel-provider-systemextension";
pub(crate) const APPROVED_TEAM_ID: &str = "TEAMID0000";
pub(crate) const PROVIDER_APP_GROUP: &str = "group.TEAMID0000.dev.aegis.macos";
type CfRef = *const c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecTaskCreateFromSelf(allocator: CfRef) -> CfRef;
    fn SecTaskCopyValueForEntitlement(task: CfRef, entitlement: CfRef, error: *mut CfRef) -> CfRef;
    fn SecCodeCopySelf(flags: u32, code: *mut CfRef) -> i32;
    fn SecRequirementCreateWithString(text: CfRef, flags: u32, requirement: *mut CfRef) -> i32;
    fn SecCodeCheckValidity(code: CfRef, flags: u32, requirement: CfRef) -> i32;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: CfRef);
    fn CFGetTypeID(value: CfRef) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFArrayGetTypeID() -> usize;
    fn CFArrayGetCount(value: CfRef) -> isize;
    fn CFArrayGetValueAtIndex(value: CfRef, index: isize) -> CfRef;
    fn CFStringGetCString(value: CfRef, buffer: *mut i8, size: isize, encoding: u32) -> u8;
}
fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "AppGroup protected input admission refused",
    )
}
pub(crate) const CUSTODY_CONTAINER_ERRNO: &str = "custody_container_errno";
/// The canonical container could not be opened by its absolute path for a
/// reason other than ENOENT. Kept distinct from a policy refusal so the real
/// sandbox's denial (errno) can be measured on an installed provider.
#[derive(Debug)]
pub(crate) struct CustodyContainerErrno(i32);
impl std::fmt::Display for CustodyContainerErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{CUSTODY_CONTAINER_ERRNO} {}", self.0)
    }
}
impl std::error::Error for CustodyContainerErrno {}
/// The held container descriptor does not (or can no longer be shown to)
/// name the canonical container path: F_GETPATH failed or differed.
pub(crate) const CUSTODY_CONTAINER_PATH_MISMATCH: &str = "custody_container_path_mismatch";
/// A directory above the container is not a root/owner-owned directory that
/// only its owner can write. Checked by path; no descriptor is held there.
pub(crate) const CUSTODY_CONTAINER_ANCESTOR_REFUSED: &str = "custody_container_ancestor_refused";
pub(crate) const CUSTODY_CONTAINER_ANCESTOR_ERRNO: &str = "custody_container_ancestor_errno";
/// lstat(2) of a directory above the container failed. Kept distinct from
/// the owner/mode refusal so a sandbox denial (errno) is never reported as a
/// policy refusal.
#[derive(Debug)]
pub(crate) struct CustodyContainerAncestorErrno(i32);
impl std::fmt::Display for CustodyContainerAncestorErrno {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{CUSTODY_CONTAINER_ANCESTOR_ERRNO} {}", self.0)
    }
}
impl std::error::Error for CustodyContainerAncestorErrno {}
pub(crate) const CONTAINER_UNRESOLVED: &str = "container_unresolved";
pub(crate) const AEGIS_TREE_MISSING: &str = "aegis_tree_missing";
/// A stable, path-free capture sub-code: the container did not resolve, or a
/// fixed leaf of the tree is absent (ENOENT). Every other refusal stays opaque.
#[derive(Debug)]
struct CustodyCode(&'static str);
impl std::fmt::Display for CustodyCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CustodyCode {}
fn custody_code(code: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, CustodyCode(code))
}
const CREDENTIAL_MISSING: &str = "file_missing:credential";
fn container_unresolved() -> io::Error {
    custody_code(CONTAINER_UNRESOLVED)
}
/// `file_missing:<leaf>` for the fixed tree leaves. The configured credential
/// leaf is user-chosen and is never named; see `CREDENTIAL_MISSING`.
fn missing_code(leaf: &str) -> &'static str {
    match leaf {
        "Aegis" => AEGIS_TREE_MISSING,
        "identity" => "file_missing:identity",
        "bundle" => "file_missing:bundle",
        "bundle.json" => "file_missing:bundle.json",
        "outer-ca.pem" => "file_missing:outer-ca.pem",
        "inner-ca.pem" => "file_missing:inner-ca.pem",
        "device-ca.pem" => "file_missing:device-ca.pem",
        ".lock" => "file_missing:.lock",
        "identity.json" => "file_missing:identity.json",
        "device.key" => "file_missing:device.key",
        "device.pem" => "file_missing:device.pem",
        "device.csr" => "file_missing:device.csr",
        "online-completed.json" => "file_missing:online-completed.json",
        "bundle-profile.sha256" => "file_missing:bundle-profile.sha256",
        _ => "file_missing:other",
    }
}
/// ENOENT names the leaf by `missing`; any other errno is opaque.
fn missing_refused(missing: &'static str, errno: i32) -> io::Error {
    if errno == libc::ENOENT {
        custody_code(missing)
    } else {
        refused()
    }
}
fn leaf_refused(leaf: &str, errno: i32) -> io::Error {
    missing_refused(missing_code(leaf), errno)
}
/// Provider failure code for a refused capture: the container open errno, an
/// ancestor lstat errno, a container path mismatch or refused ancestor, an
/// unresolved container or a missing tree leaf. Every other custody refusal
/// stays one opaque code.
/// The errno a refused capture carries, if any: the container open or an
/// ancestor lstat errno, or the error's own OS errno. Opaque refusals carry
/// none.
pub(crate) fn custody_errno(error: &io::Error) -> Option<i32> {
    let inner = error.get_ref();
    if let Some(CustodyContainerErrno(errno)) = inner.and_then(|inner| inner.downcast_ref()) {
        Some(*errno)
    } else if let Some(CustodyContainerAncestorErrno(errno)) =
        inner.and_then(|inner| inner.downcast_ref())
    {
        Some(*errno)
    } else {
        error.raw_os_error()
    }
}
pub(crate) fn custody_refusal_code(error: &io::Error) -> &'static str {
    let inner = error.get_ref();
    if inner.is_some_and(|inner| inner.is::<CustodyContainerErrno>()) {
        CUSTODY_CONTAINER_ERRNO
    } else if inner.is_some_and(|inner| inner.is::<CustodyContainerAncestorErrno>()) {
        CUSTODY_CONTAINER_ANCESTOR_ERRNO
    } else if let Some(CustodyCode(code)) = inner.and_then(|inner| inner.downcast_ref()) {
        code
    } else {
        "provider_app_group_custody_refused"
    }
}
struct CfOwned(CfRef);
impl CfOwned {
    fn admit(value: CfRef) -> io::Result<Self> {
        if value.is_null() {
            Err(refused())
        } else {
            Ok(Self(value))
        }
    }
}
impl Drop for CfOwned {
    fn drop(&mut self) {
        unsafe { CFRelease(self.0) }
    }
}
fn cf_string(value: CfRef) -> io::Result<String> {
    if value.is_null() || unsafe { CFGetTypeID(value) != CFStringGetTypeID() } {
        return Err(refused());
    }
    let mut bytes = [0i8; 1024];
    if unsafe { CFStringGetCString(value, bytes.as_mut_ptr(), bytes.len() as isize, 0x08000100) }
        == 0
    {
        return Err(refused());
    }
    let end = bytes.iter().position(|b| *b == 0).ok_or_else(refused)?;
    String::from_utf8(bytes[..end].iter().map(|b| *b as u8).collect()).map_err(|_| refused())
}
fn entitlement(task: CfRef, name: &str) -> io::Result<CfOwned> {
    let key = NSString::from_str(name);
    CfOwned::admit(unsafe {
        SecTaskCopyValueForEntitlement(
            task,
            (&*key as *const NSString).cast(),
            std::ptr::null_mut(),
        )
    })
}
fn require_entitlement_absent(task: CfRef, name: &str) -> io::Result<()> {
    let key = NSString::from_str(name);
    let mut error: CfRef = std::ptr::null();
    let value = unsafe {
        SecTaskCopyValueForEntitlement(task, (&*key as *const NSString).cast(), &mut error)
    };
    if !value.is_null() {
        unsafe { CFRelease(value) };
    }
    if !error.is_null() {
        unsafe { CFRelease(error) };
    }
    if !value.is_null() || !error.is_null() {
        return Err(refused());
    }
    Ok(())
}
fn array_contains(value: CfRef, expected: &str) -> io::Result<bool> {
    if value.is_null() || unsafe { CFGetTypeID(value) != CFArrayGetTypeID() } {
        return Err(refused());
    }
    let count = unsafe { CFArrayGetCount(value) };
    if !(1..=32).contains(&count) {
        return Err(refused());
    }
    let mut matched = false;
    for i in 0..count {
        if cf_string(unsafe { CFArrayGetValueAtIndex(value, i) })? == expected {
            matched = true;
        }
    }
    Ok(matched)
}
fn exact_provider_role(team: &str, application: &str, ne_system_extension: bool) -> bool {
    team == APPROVED_TEAM_ID
        && application == format!("{APPROVED_TEAM_ID}.{PROVIDER_BUNDLE_ID}")
        && ne_system_extension
}
fn exact_observation_child_role(team: &str, application: &str, has_ne_entitlement: bool) -> bool {
    team == APPROVED_TEAM_ID
        && application == format!("{APPROVED_TEAM_ID}.{OBSERVATION_CHILD_BUNDLE_ID}")
        && !has_ne_entitlement
}
fn exact_host_role(team: &str, application: &str, ne_system_extension: bool) -> bool {
    team == APPROVED_TEAM_ID
        && application == format!("{APPROVED_TEAM_ID}.{HOST_BUNDLE_ID}")
        && ne_system_extension
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClaimRole {
    Provider,
    Host,
    #[allow(dead_code)] // activated only after signed child/protocol review
    ObservationChild,
}
#[derive(PartialEq, Eq)]
// This proves current code signature/entitlement/container observations only.
// NE entitlement is a capability shared with a containing host, not provider
// role identity or approval of the exact intended signed release.
struct CurrentCodeAppGroupClaim {
    role: ClaimRole,
    group: String,
    team: String,
    application: String,
    container: PathBuf,
    pid: u32,
    uid: u32,
}
impl CurrentCodeAppGroupClaim {
    fn capture(group: &str) -> io::Result<Self> {
        Self::capture_role(group, ClaimRole::Provider)
    }
    fn capture_host(group: &str) -> io::Result<Self> {
        Self::capture_role(group, ClaimRole::Host)
    }
    #[allow(dead_code)] // staged child role
    fn capture_observation_child(group: &str) -> io::Result<Self> {
        Self::capture_role(group, ClaimRole::ObservationChild)
    }
    fn capture_role(group: &str, role: ClaimRole) -> io::Result<Self> {
        if group != PROVIDER_APP_GROUP {
            return Err(refused());
        }
        let task = CfOwned::admit(unsafe { SecTaskCreateFromSelf(std::ptr::null()) })?;
        let groups = entitlement(task.0, "com.apple.security.application-groups")?;
        if !array_contains(groups.0, group)? {
            return Err(refused());
        }
        let team = cf_string(entitlement(task.0, "com.apple.developer.team-identifier")?.0)?;
        let application = cf_string(entitlement(task.0, "com.apple.application-identifier")?.0)?;
        // The observation child has no NE entitlement. Treat either an API
        // error or any returned entitlement as refusal, including a different
        // NE capability; absence is checked separately from provider/host.
        let has_ne = match role {
            ClaimRole::ObservationChild => {
                require_entitlement_absent(
                    task.0,
                    "com.apple.developer.networking.networkextension",
                )?;
                false
            }
            ClaimRole::Provider | ClaimRole::Host => {
                let ne = entitlement(task.0, "com.apple.developer.networking.networkextension")?;
                array_contains(ne.0, PROVIDER_NE_ENTITLEMENT)?
            }
        };
        if !match role {
            ClaimRole::Provider => exact_provider_role(&team, &application, has_ne),
            ClaimRole::Host => exact_host_role(&team, &application, has_ne),
            ClaimRole::ObservationChild => {
                exact_observation_child_role(&team, &application, has_ne)
            }
        } {
            return Err(refused());
        }
        // Require the fixed provider code identifier as well as the observed
        // entitlement. The Team is still observed here; approved Team and
        // installed-profile admission must be supplied by release policy.
        let bundle_id = match role {
            ClaimRole::Provider => PROVIDER_BUNDLE_ID,
            ClaimRole::Host => HOST_BUNDLE_ID,
            ClaimRole::ObservationChild => OBSERVATION_CHILD_BUNDLE_ID,
        };
        let text = NSString::from_str(&format!(
            "identifier \"{bundle_id}\" and anchor apple generic and certificate leaf[subject.OU] = \"{team}\""
        ));
        let mut raw = std::ptr::null();
        if unsafe {
            SecRequirementCreateWithString((&*text as *const NSString).cast(), 0, &mut raw)
        } != 0
        {
            return Err(refused());
        }
        let requirement = CfOwned::admit(raw)?;
        let mut raw = std::ptr::null();
        if unsafe { SecCodeCopySelf(0, &mut raw) } != 0 {
            return Err(refused());
        }
        let code = CfOwned::admit(raw)?;
        if unsafe { SecCodeCheckValidity(code.0, 0, requirement.0) } != 0 {
            return Err(refused());
        }
        let identifier = NSString::from_str(group);
        let manager: Retained<AnyObject> =
            unsafe { msg_send![class!(NSFileManager), defaultManager] };
        let url: Option<Retained<AnyObject>> = unsafe {
            msg_send![&*manager,containerURLForSecurityApplicationGroupIdentifier:&*identifier]
        };
        let url = url.ok_or_else(container_unresolved)?;
        let is_file: bool = unsafe { msg_send![&*url, isFileURL] };
        if !is_file {
            return Err(container_unresolved());
        }
        let path: Option<Retained<NSString>> = unsafe { msg_send![&*url, path] };
        let path = path.ok_or_else(container_unresolved)?.to_string();
        let container =
            canonical_container(Path::new(&path)).map_err(|_| container_unresolved())?;
        Ok(Self {
            role,
            group: group.into(),
            team,
            application,
            container,
            pid: std::process::id(),
            uid: unsafe { libc::geteuid() },
        })
    }
    fn revalidate(&self) -> io::Result<()> {
        if &Self::capture_role(&self.group, self.role)? != self {
            return Err(refused());
        }
        Ok(())
    }
}
// This is only a code-signing, entitlement, and container observation. It
// intentionally exposes no Store descriptor, packet owner, or grant.
#[allow(dead_code)] // no installed child consumer in this source cut
pub(crate) struct CapturedObservationChildClaim(CurrentCodeAppGroupClaim);
#[allow(dead_code)]
impl CapturedObservationChildClaim {
    pub(crate) fn capture(group: &str) -> io::Result<Self> {
        Ok(Self(CurrentCodeAppGroupClaim::capture_observation_child(
            group,
        )?))
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.0.revalidate()
    }
}
fn clean_absolute(path: &Path) -> io::Result<()> {
    if !path.is_absolute()
        || path.as_os_str().as_encoded_bytes().len() > 4096
        || path
            .components()
            .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
    {
        return Err(refused());
    }
    Ok(())
}
/// NSFileManager reports a root extension's container through the /var
/// symlink (/var/root/Library/Group Containers/...). Resolve it once with
/// realpath(3), then require every resulting component to be a real
/// directory. `HeldContainer` re-proves the result: the descriptor it opens
/// by this path must name exactly this path (F_GETPATH).
fn canonical_container(reported: &Path) -> io::Result<PathBuf> {
    clean_absolute(reported)?;
    let canonical = std::fs::canonicalize(reported).map_err(|_| refused())?;
    clean_absolute(&canonical)?;
    let mut prefix = PathBuf::from("/");
    for part in canonical.components() {
        if let Component::Normal(leaf) = part {
            prefix.push(leaf);
            if !std::fs::symlink_metadata(&prefix)
                .map_err(|_| refused())?
                .file_type()
                .is_dir()
            {
                return Err(refused());
            }
        }
    }
    Ok(canonical)
}
fn name(path: &std::ffi::OsStr) -> io::Result<CString> {
    CString::new(path.as_encoded_bytes()).map_err(|_| refused())
}
fn owned(raw: i32) -> io::Result<File> {
    if raw < 0 {
        Err(refused())
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}
const DIRECTORY_FLAGS: i32 =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
fn last_errno() -> i32 {
    io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
fn open_directory_at(parent: &File, name: &CString) -> Result<File, i32> {
    let raw = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), DIRECTORY_FLAGS) };
    if raw < 0 {
        Err(last_errno())
    } else {
        Ok(unsafe { File::from_raw_fd(raw) })
    }
}
/// Why the canonical container could not be anchored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ContainerAnchorFailure {
    /// open(2) of the absolute path failed with this errno.
    Open(i32),
    /// fcntl(F_GETPATH) on the opened descriptor failed with this errno.
    GetPath(i32),
    /// The opened descriptor names a different path than the canonical one.
    Mismatch,
}
/// The kernel's current path for a held descriptor (F_GETPATH). On APFS it
/// is the on-disk spelling through the /private firmlink, as realpath(3)
/// reports it; a descriptor reached through a symlinked or renamed
/// component reports where it actually is.
fn held_path(file: &File) -> Result<Vec<u8>, i32> {
    // F_GETPATH writes at most MAXPATHLEN (PATH_MAX) bytes, NUL included.
    let mut buffer = [0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, buffer.as_mut_ptr()) } < 0 {
        return Err(last_errno());
    }
    let end = buffer
        .iter()
        .position(|b| *b == 0)
        .ok_or(libc::ENAMETOOLONG)?;
    Ok(buffer[..end].to_vec())
}
/// Exact byte equality with the canonical path. A case, normalization or
/// firmlink spelling difference is a mismatch, never a near match.
fn require_held_path(file: &File, canonical: &Path) -> Result<(), ContainerAnchorFailure> {
    match held_path(file) {
        Err(errno) => Err(ContainerAnchorFailure::GetPath(errno)),
        Ok(path) if path.as_slice() == canonical.as_os_str().as_encoded_bytes() => Ok(()),
        Ok(_) => Err(ContainerAnchorFailure::Mismatch),
    }
}
/// Open the canonical container by its absolute path, once: O_DIRECTORY and
/// O_NOFOLLOW on the final component. An intermediate symlink or a swapped
/// component is then caught because the held descriptor must name exactly
/// `canonical`. The sandboxed provider cannot open the container's
/// ancestors (EPERM on /private), so no descriptor above it is opened.
pub(crate) fn open_container_anchor(canonical: &Path) -> Result<File, ContainerAnchorFailure> {
    let path = CString::new(canonical.as_os_str().as_encoded_bytes())
        .map_err(|_| ContainerAnchorFailure::Open(libc::EINVAL))?;
    let raw = unsafe { libc::open(path.as_ptr(), DIRECTORY_FLAGS) };
    if raw < 0 {
        return Err(ContainerAnchorFailure::Open(last_errno()));
    }
    let file = unsafe { File::from_raw_fd(raw) };
    require_held_path(&file, canonical)?;
    Ok(file)
}
/// ENOENT is an unresolved container; any other open errno is reported as
/// the container errno sub-code; an unproven path is its own sub-code.
fn anchor_refused(failure: ContainerAnchorFailure) -> io::Error {
    match failure {
        ContainerAnchorFailure::Open(libc::ENOENT) => container_unresolved(),
        ContainerAnchorFailure::Open(errno) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            CustodyContainerErrno(errno),
        ),
        ContainerAnchorFailure::GetPath(_) | ContainerAnchorFailure::Mismatch => {
            custody_code(CUSTODY_CONTAINER_PATH_MISMATCH)
        }
    }
}
/// Why one directory above the container was not admitted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AncestorFailure {
    /// lstat(2) of the ancestor's path failed with this errno.
    Lstat(i32),
    /// Not a real directory owned by root or the uid, or group/other
    /// writable.
    Policy,
}
/// One directory above the container, by path (lstat): a real directory
/// owned by root or `uid` that group and other cannot write.
fn check_container_ancestor(ancestor: &Path, uid: u32) -> Result<(), AncestorFailure> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::symlink_metadata(ancestor)
        .map_err(|error| AncestorFailure::Lstat(error.raw_os_error().unwrap_or(libc::EIO)))?;
    if !m.file_type().is_dir() || m.uid() != 0 && m.uid() != uid || m.mode() & 0o022 != 0 {
        return Err(AncestorFailure::Policy);
    }
    Ok(())
}
/// Capture's verdict for every directory above `container`, `/` first. The
/// ping reports exactly these outcomes, so it shows what capture will see.
/// lstat is expected to be permitted by the sandbox where open is denied;
/// that is not yet measured on an installed provider.
pub(crate) fn container_ancestor_checks(
    container: &Path,
    uid: u32,
) -> Vec<(&Path, Result<(), AncestorFailure>)> {
    let mut checks: Vec<_> = container
        .ancestors()
        .skip(1)
        .map(|ancestor| (ancestor, check_container_ancestor(ancestor, uid)))
        .collect();
    checks.reverse();
    checks
}
fn ancestor_refused(failure: AncestorFailure) -> io::Error {
    match failure {
        AncestorFailure::Lstat(errno) => io::Error::new(
            io::ErrorKind::PermissionDenied,
            CustodyContainerAncestorErrno(errno),
        ),
        AncestorFailure::Policy => custody_code(CUSTODY_CONTAINER_ANCESTOR_REFUSED),
    }
}
/// Every directory above the canonical container must pass
/// `check_container_ancestor`. Under that precondition no other non-root
/// principal can rename or replace a component between realpath, the anchor
/// open and any revalidation. No descriptor is held above the container. The
/// first refusal, `/` first, is reported: an lstat errno by its own sub-code.
fn admit_container_ancestors(container: &Path, uid: u32) -> io::Result<()> {
    container_ancestor_checks(container, uid)
        .into_iter()
        .try_for_each(|(_, outcome)| outcome.map_err(ancestor_refused))
}
/// Capture's owner/mode admission of the opened container descriptor
/// (`admit_directory`, not private). Shared with the ping.
pub(crate) fn container_admitted(file: &File, uid: u32) -> bool {
    generation(file).is_ok_and(|g| admit_directory(&g, uid, false).is_ok())
}
#[derive(Clone, PartialEq, Eq)]
struct Generation {
    dev: u64,
    ino: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    size: i64,
    mtime: (i64, i64),
    ctime: (i64, i64),
}
fn generation(file: &File) -> io::Result<Generation> {
    use std::os::unix::fs::MetadataExt;
    let m = file.metadata()?;
    let size = i64::try_from(m.size()).map_err(|_| refused())?;
    Ok(Generation {
        dev: m.dev(),
        ino: m.ino(),
        uid: m.uid(),
        gid: m.gid(),
        mode: m.mode(),
        links: m.nlink(),
        size,
        mtime: (m.mtime(), m.mtime_nsec()),
        ctime: (m.ctime(), m.ctime_nsec()),
    })
}
struct HeldDirectory {
    parent: File,
    name: CString,
    file: File,
    generation: Generation,
}
impl HeldDirectory {
    fn open(parent: &File, leaf: &std::ffi::OsStr, uid: u32, private: bool) -> io::Result<Self> {
        let name = name(leaf)?;
        let file = open_directory_at(parent, &name)
            .map_err(|errno| leaf_refused(&leaf.to_string_lossy(), errno))?;
        Self::admit(parent, name, file, uid, private)
    }
    fn admit(
        parent: &File,
        name: CString,
        file: File,
        uid: u32,
        private: bool,
    ) -> io::Result<Self> {
        let g = generation(&file)?;
        admit_directory(&g, uid, private)?;
        Ok(Self {
            parent: parent.try_clone()?,
            name,
            file,
            generation: g,
        })
    }
    fn revalidate(&self) -> io::Result<()> {
        let named = open_directory_at(&self.parent, &self.name).map_err(|_| refused())?;
        if generation(&self.file)? != self.generation || generation(&named)? != self.generation {
            return Err(refused());
        }
        Ok(())
    }
    fn revalidate_named_inode(&self) -> io::Result<()> {
        let named = open_directory_at(&self.parent, &self.name).map_err(|_| refused())?;
        let same = |current: &Generation| {
            current.dev == self.generation.dev
                && current.ino == self.generation.ino
                && current.uid == self.generation.uid
                && current.gid == self.generation.gid
                && current.mode == self.generation.mode
        };
        if !same(&generation(&self.file)?) || !same(&generation(&named)?) {
            return Err(refused());
        }
        Ok(())
    }
    fn refresh_after_owned_mutation(&mut self) -> io::Result<()> {
        self.revalidate_named_inode()?;
        self.generation = generation(&self.file)?;
        self.revalidate()
    }
}
/// A directory owned by root or `uid`, writable by its owner only; a private
/// directory is additionally owned by `uid` with mode 0700 exactly.
fn admit_directory(g: &Generation, uid: u32, private: bool) -> io::Result<()> {
    if g.mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32
        || !matches!(g.uid, 0) && g.uid != uid
        || g.mode & 0o022 != 0
        || private && (g.uid != uid || g.mode & 0o7777 != 0o700)
    {
        return Err(refused());
    }
    Ok(())
}
/// Descriptor hold anchored at the App Group container itself, opened once
/// by its canonical absolute path. The held descriptor must keep naming that
/// path (F_GETPATH), the path must keep resolving to the same directory, and
/// the container keeps the full generation check, as does the Aegis tree
/// below it. No descriptor above the container is held: the sandboxed
/// provider cannot open its ancestors.
pub(crate) struct HeldContainer {
    path: PathBuf,
    uid: u32,
    file: File,
    generation: Generation,
}
impl HeldContainer {
    pub(crate) fn open(container: &Path, uid: u32) -> io::Result<Self> {
        clean_absolute(container)?;
        // `/` itself is never an App Group container.
        if container.parent().is_none() {
            return Err(refused());
        }
        admit_container_ancestors(container, uid)?;
        let file = open_container_anchor(container).map_err(anchor_refused)?;
        let generation = generation(&file)?;
        admit_directory(&generation, uid, false)?;
        Ok(Self {
            path: container.to_owned(),
            uid,
            file,
            generation,
        })
    }
    pub(crate) fn file(&self) -> &File {
        &self.file
    }
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
    /// The held descriptor is still the directory at the canonical path,
    /// re-proved like `revalidate` (ancestors, fresh anchor with F_GETPATH)
    /// but on dev/ino/owner/mode only: an owner that creates or renames
    /// entries inside the container changes its mtime, ctime and size.
    pub(crate) fn revalidate_identity(&self) -> io::Result<()> {
        admit_container_ancestors(&self.path, self.uid)?;
        let named = open_container_anchor(&self.path).map_err(anchor_refused)?;
        let same = |current: &Generation| {
            current.dev == self.generation.dev
                && current.ino == self.generation.ino
                && current.uid == self.generation.uid
                && current.gid == self.generation.gid
                && current.mode == self.generation.mode
        };
        if !same(&generation(&self.file)?) || !same(&generation(&named)?) {
            return Err(refused());
        }
        Ok(())
    }
    fn revalidate(&self) -> io::Result<()> {
        admit_container_ancestors(&self.path, self.uid)?;
        // A fresh anchor at the canonical path (F_GETPATH re-proved) whose
        // generation, dev/ino included, equals the held one: the held
        // directory is therefore still the one at that exact path.
        let named = open_container_anchor(&self.path).map_err(anchor_refused)?;
        if generation(&self.file)? != self.generation || generation(&named)? != self.generation {
            return Err(refused());
        }
        Ok(())
    }
}
struct HeldPrivateFile {
    parent: File,
    name: CString,
    file: File,
    generation: Generation,
}
impl HeldPrivateFile {
    fn open(parent: &File, leaf: &str, uid: u32) -> io::Result<Self> {
        Self::open_as(parent, leaf, missing_code(leaf), uid)
    }
    fn open_as(parent: &File, leaf: &str, missing: &'static str, uid: u32) -> io::Result<Self> {
        let name = CString::new(leaf).map_err(|_| refused())?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(missing_refused(missing, last_errno()));
        }
        let file = owned(raw)?;
        Self::from_file(parent, name, file, uid)
    }
    fn from_file(parent: &File, name: CString, file: File, uid: u32) -> io::Result<Self> {
        let g = generation(&file)?;
        if g.uid != uid
            || g.mode != (libc::S_IFREG as u32 | 0o600)
            || g.links != 1
            || g.size < 0
            || g.size as u64 > MAX_FILE
        {
            return Err(refused());
        }
        Ok(Self {
            parent: parent.try_clone()?,
            name,
            file,
            generation: g,
        })
    }
    fn revalidate(&self) -> io::Result<()> {
        let named = owned(unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        })?;
        if generation(&self.file)? != self.generation || generation(&named)? != self.generation {
            return Err(refused());
        }
        Ok(())
    }
    fn with_file<T>(&mut self, read: impl FnOnce(&mut File) -> io::Result<T>) -> io::Result<T> {
        self.revalidate()?;
        let result = (|| {
            self.file.seek(SeekFrom::Start(0))?;
            read(&mut self.file)
        })();
        // Revalidation runs on callback/seek failure too. Lost custody takes
        // precedence over a parser error and never leaves a successful lease.
        self.revalidate()?;
        result
    }
    fn read_bounded_private(&self, limit: usize) -> io::Result<Zeroizing<Vec<u8>>> {
        use std::os::unix::fs::FileExt;
        if limit > MAX_FILE as usize {
            return Err(refused());
        }
        self.revalidate()?;
        // Reserve the entire accepted length before any private byte arrives.
        // Appending at most `limit` bytes cannot reallocate and leave an old
        // secret allocation outside the Zeroizing owner.
        let mut bytes = Zeroizing::new(Vec::with_capacity(limit));
        // Both buffers are guarded before the first read, including every
        // short read, over-limit, metadata and I/O error path.
        let mut part = Zeroizing::new([0u8; 4096]);
        loop {
            let count = self
                .file
                .read_at(&mut part[..], bytes.len() as u64)
                .map_err(|_| refused())?;
            if count == 0 {
                break;
            }
            if bytes.len().saturating_add(count) > limit {
                return Err(refused());
            }
            bytes.extend_from_slice(&part[..count]);
        }
        self.revalidate()?;
        Ok(bytes)
    }
}
struct CapturedBridge {
    sidecar: HeldPrivateFile,
    credential: HeldPrivateFile,
    sidecar_bytes: Zeroizing<Vec<u8>>,
    secret: Zeroizing<[u8; 64]>,
    settings: BridgeSettings,
}

pub(crate) struct CapturedBridgeSnapshot {
    pub(crate) settings: BridgeSettings,
    // The exact credential is retained in memory for a future prepared H2
    // request. It is never reconstructed from the mutable path after capture.
    pub(crate) secret: Zeroizing<[u8; 64]>,
}

/// Exact bytes read from the descriptors retained by one App Group owner.
/// Private key material is guarded before the first read and on all errors.
pub(crate) struct CapturedCryptoPayload {
    pub(crate) outer_ca: Vec<u8>,
    pub(crate) inner_ca: Vec<u8>,
    pub(crate) certificate: Vec<u8>,
    pub(crate) private_key: Zeroizing<Vec<u8>>,
    pub(crate) bridge: Option<CapturedBridgeSnapshot>,
    pub(crate) web_response: Option<CapturedWebResponseSnapshot>,
}

/// Held D5 admission policy and key. Capture alone is no WebClient grant:
/// the signed route, exact ingress, inner identity and ACK are still required.
pub(crate) struct CapturedWebResponseSnapshot {
    pub(crate) settings: WebResponseSettings,
    pub(crate) secret: Zeroizing<[u8; 64]>,
}

struct CapturedWebResponse {
    sidecar: HeldPrivateFile,
    credential: HeldPrivateFile,
    sidecar_bytes: Zeroizing<Vec<u8>>,
    settings: WebResponseSettings,
    secret: Zeroizing<[u8; 64]>,
}
impl CapturedWebResponse {
    fn capture(
        sidecar: HeldPrivateFile,
        identity: &HeldDirectory,
        path: &Path,
        uid: u32,
    ) -> io::Result<Self> {
        let sidecar_bytes = sidecar.read_bounded_private(8192)?;
        let (settings, leaf) = crate::web_response_custody::admit_sidecar(&sidecar_bytes, path)?;
        let credential = HeldPrivateFile::open_as(&identity.file, &leaf, CREDENTIAL_MISSING, uid)?;
        let raw = credential.read_bounded_private(65)?;
        let secret = crate::web_response_custody::admit_key(&raw)?;
        let result = Self {
            sidecar,
            credential,
            sidecar_bytes,
            settings,
            secret,
        };
        result.revalidate()?;
        Ok(result)
    }
    fn revalidate(&self) -> io::Result<()> {
        let actual_sidecar = self.sidecar.read_bounded_private(8192)?;
        let raw = self.credential.read_bounded_private(65)?;
        let actual_key = crate::web_response_custody::admit_key(&raw)?;
        if actual_sidecar.as_slice() != self.sidecar_bytes.as_slice()
            || actual_key
                .as_slice()
                .ct_eq(self.secret.as_slice())
                .unwrap_u8()
                != 1
        {
            return Err(refused());
        }
        Ok(())
    }
    fn snapshot(&self) -> CapturedWebResponseSnapshot {
        let mut secret = Zeroizing::new([0u8; 64]);
        secret.copy_from_slice(self.secret.as_slice());
        CapturedWebResponseSnapshot {
            settings: self.settings.clone(),
            secret,
        }
    }
}

enum CapturedWebResponseState {
    Absent,
    Present(Box<CapturedWebResponse>),
}
impl CapturedWebResponseState {
    fn capture(identity: &HeldDirectory, path: &Path, uid: u32) -> io::Result<Self> {
        let name =
            CString::new(aegis_client::device_web_response::SIDECAR).map_err(|_| refused())?;
        let raw = unsafe {
            libc::openat(
                identity.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(Self::Absent);
            }
            return Err(refused());
        }
        let sidecar = HeldPrivateFile::from_file(&identity.file, name, owned(raw)?, uid)?;
        Ok(Self::Present(Box::new(CapturedWebResponse::capture(
            sidecar, identity, path, uid,
        )?)))
    }
    fn revalidate(&self, identity: &HeldDirectory) -> io::Result<()> {
        match self {
            Self::Present(web) => web.revalidate(),
            Self::Absent => {
                let name = CString::new(aegis_client::device_web_response::SIDECAR)
                    .map_err(|_| refused())?;
                let raw = unsafe {
                    libc::openat(
                        identity.file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw >= 0 {
                    drop(owned(raw)?);
                    return Err(refused());
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(refused());
                }
                Ok(())
            }
        }
    }
}

/// One retained SFU key and two independently pinned trust roots. These
/// bytes grant no network access until the signed declaration, live broker
/// grant, exact ICE candidates and current packet arm are all validated.
pub(crate) struct CapturedSfuSnapshot {
    pub(crate) broker_key: Zeroizing<[u8; 64]>,
    pub(crate) broker_ca: Vec<u8>,
    pub(crate) media_ca: Vec<u8>,
}

struct CapturedSfu {
    sidecar: HeldPrivateFile,
    key: HeldPrivateFile,
    broker_ca: HeldPrivateFile,
    media_ca: HeldPrivateFile,
    sidecar_bytes: Zeroizing<Vec<u8>>,
    key_bytes: Zeroizing<[u8; 64]>,
    broker_ca_bytes: Vec<u8>,
    media_ca_bytes: Vec<u8>,
}

impl CapturedSfu {
    fn capture(
        sidecar: HeldPrivateFile,
        identity: &HeldDirectory,
        path: &Path,
        uid: u32,
    ) -> io::Result<Self> {
        let sidecar_bytes = sidecar.read_bounded_private(8192)?;
        crate::sfu_media_custody::admit_sidecar(&sidecar_bytes, path)?;
        let key = HeldPrivateFile::open_as(
            &identity.file,
            crate::sfu_media_custody::BROKER_KEY,
            CREDENTIAL_MISSING,
            uid,
        )?;
        let broker_ca = HeldPrivateFile::open_as(
            &identity.file,
            crate::sfu_media_custody::BROKER_CA,
            CREDENTIAL_MISSING,
            uid,
        )?;
        let media_ca = HeldPrivateFile::open_as(
            &identity.file,
            crate::sfu_media_custody::MEDIA_CA,
            CREDENTIAL_MISSING,
            uid,
        )?;
        let key_bytes = crate::sfu_media_custody::admit_broker_key(&key.read_bounded_private(65)?)?;
        let broker_ca_bytes = broker_ca.read_bounded_private(64 * 1024)?.to_vec();
        let media_ca_bytes = media_ca.read_bounded_private(64 * 1024)?.to_vec();
        let result = Self {
            sidecar,
            key,
            broker_ca,
            media_ca,
            sidecar_bytes,
            key_bytes,
            broker_ca_bytes,
            media_ca_bytes,
        };
        result.revalidate()?;
        Ok(result)
    }

    fn revalidate(&self) -> io::Result<()> {
        let sidecar = self.sidecar.read_bounded_private(8192)?;
        let key = crate::sfu_media_custody::admit_broker_key(&self.key.read_bounded_private(65)?)?;
        let broker_ca = self.broker_ca.read_bounded_private(64 * 1024)?;
        let media_ca = self.media_ca.read_bounded_private(64 * 1024)?;
        if sidecar.as_slice() != self.sidecar_bytes.as_slice()
            || key.as_slice().ct_eq(self.key_bytes.as_slice()).unwrap_u8() != 1
            || broker_ca.as_slice() != self.broker_ca_bytes.as_slice()
            || media_ca.as_slice() != self.media_ca_bytes.as_slice()
        {
            return Err(refused());
        }
        Ok(())
    }

    fn snapshot(&self) -> CapturedSfuSnapshot {
        let mut broker_key = Zeroizing::new([0; 64]);
        broker_key.copy_from_slice(self.key_bytes.as_slice());
        CapturedSfuSnapshot {
            broker_key,
            broker_ca: self.broker_ca_bytes.clone(),
            media_ca: self.media_ca_bytes.clone(),
        }
    }
}

enum CapturedSfuState {
    Absent,
    Present(Box<CapturedSfu>),
}

impl CapturedSfuState {
    fn capture(identity: &HeldDirectory, path: &Path, uid: u32) -> io::Result<Self> {
        let name = CString::new(crate::sfu_media_custody::SIDECAR).map_err(|_| refused())?;
        let raw = unsafe {
            libc::openat(
                identity.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(Self::Absent);
            }
            return Err(refused());
        }
        let sidecar = HeldPrivateFile::from_file(&identity.file, name, owned(raw)?, uid)?;
        Ok(Self::Present(Box::new(CapturedSfu::capture(
            sidecar, identity, path, uid,
        )?)))
    }

    fn revalidate(&self, identity: &HeldDirectory) -> io::Result<()> {
        match self {
            Self::Present(sfu) => sfu.revalidate(),
            Self::Absent => {
                for leaf in [
                    crate::sfu_media_custody::SIDECAR,
                    crate::sfu_media_custody::BROKER_KEY,
                    crate::sfu_media_custody::BROKER_CA,
                    crate::sfu_media_custody::MEDIA_CA,
                ] {
                    let name = CString::new(leaf).map_err(|_| refused())?;
                    let raw = unsafe {
                        libc::openat(
                            identity.file.as_raw_fd(),
                            name.as_ptr(),
                            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        )
                    };
                    if raw >= 0 {
                        drop(owned(raw)?);
                        return Err(refused());
                    }
                    if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                        return Err(refused());
                    }
                }
                Ok(())
            }
        }
    }
}

impl CapturedBridge {
    fn snapshot(&self) -> CapturedBridgeSnapshot {
        // Allocate a zeroizing destination before copying any credential
        // byte. Dereferencing the source array would make an unguarded stack
        // temporary, even if the destination were subsequently wrapped.
        let mut secret = Zeroizing::new([0u8; 64]);
        secret.copy_from_slice(self.secret.as_slice());
        CapturedBridgeSnapshot {
            settings: self.settings.clone(),
            secret,
        }
    }
    fn capture(
        sidecar: HeldPrivateFile,
        identity: &HeldDirectory,
        path: &Path,
        uid: u32,
    ) -> io::Result<Self> {
        let sidecar_bytes = sidecar.read_bounded_private(8192)?;
        let input = std::str::from_utf8(&sidecar_bytes).map_err(|_| refused())?;
        let mut settings: BridgeSettings = toml::from_str(input).map_err(|_| refused())?;
        settings.validate().map_err(|_| refused())?;
        // R16 permits a single direct identity child. Anything outside the
        // retained directory needs a separately reviewed descriptor chain.
        // `path` is the realpath while a writer may use the spelling
        // NSFileManager reports (/var/...); the parent is resolved only to
        // name the held directory and the leaf is opened through its fd.
        let credential_file = settings.credential_file.clone();
        let leaf = Some(credential_file.as_path())
            .filter(|file| {
                file.parent().is_some_and(|parent| {
                    parent == path || std::fs::canonicalize(parent).is_ok_and(|real| real == path)
                })
            })
            .and_then(|file| file.file_name())
            .and_then(|name| name.to_str())
            .filter(|name| {
                ![
                    "device.key",
                    "device.pem",
                    "device-ca.pem",
                    "identity.json",
                    "bundle-profile.sha256",
                    SIDECAR,
                    ".lock",
                ]
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
            })
            .ok_or_else(refused)?;
        let credential = HeldPrivateFile::open_as(&identity.file, leaf, CREDENTIAL_MISSING, uid)?;
        // Downstream policy sees the held tree's spelling, never the alias.
        settings.credential_file = path.join(leaf);
        let bytes = credential.read_bounded_private(65)?;
        let value = bytes.strip_suffix(b"\n").unwrap_or(&bytes);
        if value.len() != 64
            || value
                .iter()
                .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(b))
            || value.iter().all(|b| *b == b'0')
        {
            return Err(refused());
        }
        let mut secret = Zeroizing::new([0; 64]);
        secret.copy_from_slice(value);
        let result = Self {
            sidecar,
            credential,
            sidecar_bytes,
            secret,
            settings,
        };
        result.revalidate()?;
        Ok(result)
    }
    fn revalidate(&self) -> io::Result<()> {
        let raw = self.credential.read_bounded_private(65)?;
        let actual = raw.strip_suffix(b"\n").unwrap_or(&raw);
        if self.sidecar.read_bounded_private(8192)?.as_slice() != self.sidecar_bytes.as_slice()
            || actual.ct_eq(self.secret.as_slice()).unwrap_u8() != 1
        {
            return Err(refused());
        }
        Ok(())
    }
}

enum CapturedBridgeState {
    Absent,
    Present(Box<CapturedBridge>),
}
impl CapturedBridgeState {
    fn capture(identity: &HeldDirectory, path: &Path, uid: u32) -> io::Result<Self> {
        let name = CString::new(SIDECAR).map_err(|_| refused())?;
        let raw = unsafe {
            libc::openat(
                identity.file.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                return Ok(Self::Absent);
            }
            return Err(refused());
        }
        let sidecar = HeldPrivateFile::from_file(&identity.file, name, owned(raw)?, uid)?;
        Ok(Self::Present(Box::new(CapturedBridge::capture(
            sidecar, identity, path, uid,
        )?)))
    }
    fn revalidate(&self, identity: &HeldDirectory) -> io::Result<()> {
        match self {
            Self::Present(bridge) => bridge.revalidate(),
            Self::Absent => {
                let name = CString::new(SIDECAR).map_err(|_| refused())?;
                let raw = unsafe {
                    libc::openat(
                        identity.file.as_raw_fd(),
                        name.as_ptr(),
                        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )
                };
                if raw >= 0 {
                    drop(owned(raw)?);
                    return Err(refused());
                }
                if io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                    return Err(refused());
                }
                Ok(())
            }
        }
    }
}
/// The four public profile members, opened in `MEMBERS` (digest) order.
struct HeldPublicFiles {
    bundle: HeldPrivateFile,
    outer_ca: HeldPrivateFile,
    inner_ca: HeldPrivateFile,
    device_ca: HeldPrivateFile,
}
impl HeldPublicFiles {
    fn open(directory: &File, uid: u32) -> io::Result<Self> {
        let [bundle, outer_ca, inner_ca, device_ca] = MEMBERS;
        Ok(Self {
            bundle: HeldPrivateFile::open(directory, bundle, uid)?,
            outer_ca: HeldPrivateFile::open(directory, outer_ca, uid)?,
            inner_ca: HeldPrivateFile::open(directory, inner_ca, uid)?,
            device_ca: HeldPrivateFile::open(directory, device_ca, uid)?,
        })
    }
    fn revalidate(&self) -> io::Result<()> {
        for file in [
            &self.bundle,
            &self.outer_ca,
            &self.inner_ca,
            &self.device_ca,
        ] {
            file.revalidate()?;
        }
        Ok(())
    }
    fn read(&mut self) -> io::Result<[Vec<u8>; 4]> {
        let mut payload: [Vec<u8>; 4] = std::array::from_fn(|_| Vec::new());
        let members = [
            &mut self.bundle,
            &mut self.outer_ca,
            &mut self.inner_ca,
            &mut self.device_ca,
        ];
        for (file, bytes) in members.into_iter().zip(&mut payload) {
            file.with_file(|opened| {
                opened
                    .take(MAX_PUBLIC_BYTES + 1)
                    .read_to_end(bytes)
                    .map_err(|_| refused())?;
                if bytes.len() as u64 > MAX_PUBLIC_BYTES
                    || bytes
                        .windows(b"PRIVATE KEY".len())
                        .any(|v| v == b"PRIVATE KEY")
                {
                    return Err(refused());
                }
                Ok(())
            })?;
        }
        Ok(payload)
    }
    fn digest(&mut self) -> io::Result<String> {
        Ok(profile_digest_bytes(&self.read()?))
    }
}
/// The portable identity Store holds `.lock` while checking issuance.
/// Capture its inode too: replacing the lock would split ownership even when
/// all identity payload files still match this generation. The CSR and the
/// completion receipt are held as well (S22). The online transaction journal
/// must be absent at capture; one created later changes the held identity
/// directory generation, which every revalidation compares.
struct HeldIdentityFiles {
    lock: HeldPrivateFile,
    record: HeldPrivateFile,
    device_key: HeldPrivateFile,
    device_csr: HeldPrivateFile,
    device_certificate: HeldPrivateFile,
    device_ca: HeldPrivateFile,
    profile_pin: HeldPrivateFile,
    completion: HeldPrivateFile,
}
/// Byte bounds of the held identity reads: the Store's ordinary (64 KiB) and
/// online (256 KiB) reads.
const MAX_IDENTITY_BYTES: usize = 64 * 1024;
const MAX_ONLINE_BYTES: usize = 256 * 1024;
/// Any entry (file, directory or link) at a journal leaf refuses with
/// `identity_journal_pending`; an errno other than ENOENT stays opaque.
fn journal_absent(directory: &File) -> io::Result<()> {
    for leaf in identity_custody::JOURNAL {
        let name = CString::new(leaf).map_err(|_| refused())?;
        let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe {
            libc::fstatat(
                directory.as_raw_fd(),
                name.as_ptr(),
                stat.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0
        {
            return Err(custody_code(identity_custody::JOURNAL_PENDING));
        }
        if last_errno() != libc::ENOENT {
            return Err(refused());
        }
    }
    Ok(())
}
impl HeldIdentityFiles {
    fn open(directory: &File, uid: u32) -> io::Result<Self> {
        journal_absent(directory)?;
        Ok(Self {
            lock: HeldPrivateFile::open(directory, ".lock", uid)?,
            record: HeldPrivateFile::open(directory, "identity.json", uid)?,
            device_key: HeldPrivateFile::open(directory, "device.key", uid)?,
            device_csr: HeldPrivateFile::open(directory, "device.csr", uid)?,
            device_certificate: HeldPrivateFile::open(directory, "device.pem", uid)?,
            device_ca: HeldPrivateFile::open(directory, "device-ca.pem", uid)?,
            profile_pin: HeldPrivateFile::open(directory, "bundle-profile.sha256", uid)?,
            completion: HeldPrivateFile::open(directory, "online-completed.json", uid)?,
        })
    }
    fn revalidate(&self) -> io::Result<()> {
        for file in [
            &self.lock,
            &self.record,
            &self.device_key,
            &self.device_csr,
            &self.device_certificate,
            &self.device_ca,
            &self.profile_pin,
            &self.completion,
        ] {
            file.revalidate()?;
        }
        Ok(())
    }
    /// The held record, key, CSR, certificate and receipt checked against
    /// each other and the held public digest (`identity_custody::verify`).
    fn issuance(&self, profile_sha256: &str) -> io::Result<HeldIssuance> {
        let record = self.record.read_bounded_private(MAX_IDENTITY_BYTES)?;
        let key = self.device_key.read_bounded_private(MAX_IDENTITY_BYTES)?;
        let csr = self.device_csr.read_bounded_private(MAX_IDENTITY_BYTES)?;
        let certificate = self
            .device_certificate
            .read_bounded_private(MAX_IDENTITY_BYTES)?;
        let device_ca = self.device_ca.read_bounded_private(MAX_IDENTITY_BYTES)?;
        let completion = self.completion.read_bounded_private(MAX_ONLINE_BYTES)?;
        identity_custody::verify(
            &HeldIdentityBytes {
                record: &record,
                key: &key,
                csr: &csr,
                certificate: &certificate,
                device_ca: &device_ca,
                completion: &completion,
            },
            profile_sha256,
        )
        .map_err(custody_code)
    }
}
enum CaptureAuthority {
    Signed(CurrentCodeAppGroupClaim),
    // Unsigned lib tests have no App Group entitlement. This variant exists
    // only in cfg(test) builds; descriptor custody below it is unchanged.
    #[cfg(test)]
    TestRoot {
        container: PathBuf,
        uid: u32,
    },
}
impl CaptureAuthority {
    fn container(&self) -> &Path {
        match self {
            Self::Signed(claim) => &claim.container,
            #[cfg(test)]
            Self::TestRoot { container, .. } => container,
        }
    }
    fn uid(&self) -> u32 {
        match self {
            Self::Signed(claim) => claim.uid,
            #[cfg(test)]
            Self::TestRoot { uid, .. } => *uid,
        }
    }
    fn revalidate(&self) -> io::Result<()> {
        match self {
            Self::Signed(claim) => claim.revalidate(),
            #[cfg(test)]
            Self::TestRoot { .. } => Ok(()),
        }
    }
}
/// Capture-only code/entitlement claim plus held native inputs, NOT approval
/// of provider role. An independently admitted exact provider code identifier
/// and Apple provisioning/profile evidence are still required before a factory.
/// No key/certificate bytes, debug formatting,
/// environment setting or factory constructor is exposed. Actual PKI/lease and
/// permission ACK validation remain in the portable product implementation.
/// `Aegis/runtime.json` is never opened, held or read here: the provider
/// derives its runtime binding from the held tree (see `runtime_binding`). A
/// leaf created or removed under `Aegis/` after capture still changes the held
/// directory generation and fails revalidation.
pub struct CapturedAppGroupInputs {
    authority: CaptureAuthority,
    container: HeldContainer,
    root: HeldDirectory,
    identity: HeldDirectory,
    bundle_directory: HeldDirectory,
    public: HeldPublicFiles,
    identity_files: HeldIdentityFiles,
    bridge: CapturedBridgeState,
    web_response: CapturedWebResponseState,
    sfu_media: CapturedSfuState,
    /// The held completion receipt's issuance (S22), checked at capture.
    issuance: HeldIssuance,
    bundle: PathBuf,
    identity_path: PathBuf,
    /// The provider tree lease (S14): while any provider capture exists, an
    /// identity import or forget is refused. Acquired before the first
    /// filesystem access and dropped last, after every held descriptor.
    _lease: Option<TreeLease>,
}
impl CapturedAppGroupInputs {
    /// Provider capture. The tree lease is taken first, so an import or
    /// forget in progress finishes (or is refused) before any descriptor of
    /// the tree is opened, and none can start while this capture exists.
    pub fn capture_claim(group: &str) -> io::Result<Self> {
        let lease = PROVIDER_TREE_GATE.lease();
        Self::capture_from_authority(
            CaptureAuthority::Signed(CurrentCodeAppGroupClaim::capture(group)?),
            Some(lease),
        )
    }

    /// The public-terms capture for the unauthenticated `profile-terms` verb:
    /// the same signed claim and checks under a transient read lease, so it
    /// never makes an import or forget look like a live session, and an
    /// import or forget waits only a bounded time for it (`READER_DRAIN`).
    pub fn capture_terms_claim(group: &str) -> io::Result<Self> {
        let lease = PROVIDER_TREE_GATE.read_lease();
        Self::capture_from_authority(
            CaptureAuthority::Signed(CurrentCodeAppGroupClaim::capture(group)?),
            Some(lease),
        )
    }

    /// Unsigned lib-test capture of `dir/Aegis` with uid = euid. Only the code
    /// signature claim is skipped; the same canonical container anchor
    /// (`HeldContainer::open`) and every held descriptor check still apply.
    #[cfg(test)]
    pub(crate) fn capture_test_root(dir: &Path) -> io::Result<Self> {
        if canonical_container(dir)? != dir {
            return Err(refused());
        }
        Self::capture_from_authority(
            CaptureAuthority::TestRoot {
                container: dir.to_owned(),
                uid: unsafe { libc::geteuid() },
            },
            None,
        )
    }

    /// `capture_test_root` holding a lease of `gate`, as a provider session
    /// holds the production gate for its lifetime.
    #[cfg(test)]
    pub(crate) fn capture_test_root_leased(
        dir: &Path,
        gate: &'static crate::identity_import::TreeGate,
    ) -> io::Result<Self> {
        let lease = gate.lease();
        let mut inputs = Self::capture_test_root(dir)?;
        inputs._lease = Some(lease);
        Ok(inputs)
    }

    /// `capture_test_root` holding a read lease of `gate`, as the public
    /// terms capture holds the production gate (`capture_terms_claim`).
    #[cfg(test)]
    pub(crate) fn capture_test_root_read_leased(
        dir: &Path,
        gate: &'static crate::identity_import::TreeGate,
    ) -> io::Result<Self> {
        let lease = gate.read_lease();
        let mut inputs = Self::capture_test_root(dir)?;
        inputs._lease = Some(lease);
        Ok(inputs)
    }

    /// The future fixed child executable can capture the same held descriptors
    /// under its *own* signed role. This opens no Store; only the child worker
    /// may consume this claim, and no provider path calls this constructor.
    #[allow(dead_code)] // child executable is not linked until installed proof
    pub(crate) fn capture_observation_child_claim() -> io::Result<Self> {
        let child = CapturedObservationChildClaim::capture(PROVIDER_APP_GROUP)?;
        Self::capture_from_authority(CaptureAuthority::Signed(child.0), None)
    }

    /// Staged ObserveChild binary entry point. It checks this process's exact
    /// signed role and held App Group files, then releases the descriptors.
    /// A successful check is not a Store, H2, packet or readiness grant.
    pub fn observation_child_staging_preflight() -> io::Result<()> {
        let inputs = Self::capture_observation_child_claim()?;
        inputs.revalidate()
    }

    fn capture_from_authority(
        authority: CaptureAuthority,
        lease: Option<TreeLease>,
    ) -> io::Result<Self> {
        let uid = authority.uid();
        let container = HeldContainer::open(authority.container(), uid)?;
        let root = HeldDirectory::open(container.file(), std::ffi::OsStr::new("Aegis"), uid, true)?;
        let identity =
            HeldDirectory::open(&root.file, std::ffi::OsStr::new("identity"), uid, true)?;
        let bundle_directory =
            HeldDirectory::open(&root.file, std::ffi::OsStr::new("bundle"), uid, true)?;
        let mut public = HeldPublicFiles::open(&bundle_directory.file, uid)?;
        let identity_files = HeldIdentityFiles::open(&identity.file, uid)?;
        let bundle = authority.container().join("Aegis/bundle");
        let identity_path = authority.container().join("Aegis/identity");
        let bridge = CapturedBridgeState::capture(&identity, &identity_path, uid)?;
        let web_response = CapturedWebResponseState::capture(&identity, &identity_path, uid)?;
        let sfu_media = CapturedSfuState::capture(&identity, &identity_path, uid)?;
        let issuance = identity_files.issuance(&public.digest()?)?;
        let owner = Self {
            authority,
            container,
            root,
            identity,
            bundle_directory,
            public,
            identity_files,
            bridge,
            web_response,
            sfu_media,
            issuance,
            bundle,
            identity_path,
            _lease: lease,
        };
        owner.revalidate()?;
        Ok(owner)
    }
    pub fn revalidate(&self) -> io::Result<()> {
        self.authority.revalidate()?;
        self.container.revalidate()?;
        self.root.revalidate()?;
        self.identity.revalidate()?;
        self.bundle_directory.revalidate()?;
        self.public.revalidate()?;
        self.identity_files.revalidate()?;
        self.bridge.revalidate(&self.identity)?;
        self.web_response.revalidate(&self.identity)?;
        self.sfu_media.revalidate(&self.identity)?;
        Ok(())
    }
    /// Digest the four public members through the exact descriptors retained
    /// by this owner. Neither a replacement leaf nor an in-place edit can be
    /// silently substituted for the admitted generation.
    pub fn captured_public_profile_digest(&mut self) -> io::Result<String> {
        self.revalidate()?;
        let digest = self.public.digest()?;
        self.revalidate()?;
        Ok(digest)
    }
    /// Require `online` (the Store's expectation under this claim) to be the
    /// held receipt's exact issuance. Refused with `identity_issuance_mismatch`.
    /// The receipt was checked at capture and its file generation is part of
    /// every revalidation, so this compares retained values only.
    pub(crate) fn ensure_held_issuance(&self, online: &OnlineExpectation) -> io::Result<()> {
        self.issuance.ensure_matches(online).map_err(custody_code)
    }
    /// S23: the held receipt's `(not_before, not_after)`, checked at capture
    /// against the held record, CSR, profile and the held certificate's own
    /// signed validity under the pinned device CA. Data only: the Store
    /// still decides whether the certificate is valid now.
    pub(crate) fn held_window(&self) -> (u64, u64) {
        self.issuance.window()
    }
    pub(crate) fn captured_bridge_snapshot(&self) -> io::Result<Option<CapturedBridgeSnapshot>> {
        self.revalidate()?;
        Ok(match &self.bridge {
            CapturedBridgeState::Absent => None,
            CapturedBridgeState::Present(bridge) => Some(bridge.snapshot()),
        })
    }
    #[allow(dead_code)] // future D5 composite owner consumes only after its own admission proof
    pub(crate) fn captured_web_response_snapshot(
        &self,
    ) -> io::Result<Option<CapturedWebResponseSnapshot>> {
        self.revalidate()?;
        Ok(match &self.web_response {
            CapturedWebResponseState::Absent => None,
            CapturedWebResponseState::Present(web) => Some(web.snapshot()),
        })
    }
    pub(crate) fn captured_sfu_media_snapshot(&self) -> io::Result<Option<CapturedSfuSnapshot>> {
        self.revalidate()?;
        Ok(match &self.sfu_media {
            CapturedSfuState::Absent => None,
            CapturedSfuState::Present(sfu) => Some(sfu.snapshot()),
        })
    }
    pub(crate) fn captured_public_payload(&mut self) -> io::Result<[Vec<u8>; 4]> {
        self.revalidate()?;
        let payload = self.public.read()?;
        self.revalidate()?;
        Ok(payload)
    }
    pub(crate) fn captured_crypto_payload(&mut self) -> io::Result<CapturedCryptoPayload> {
        self.revalidate()?;
        let public = self.public.read()?;
        let certificate = self
            .identity_files
            .device_certificate
            .read_bounded_private(MAX_FILE as usize)?;
        let private_key = self
            .identity_files
            .device_key
            .read_bounded_private(MAX_FILE as usize)?;
        let bridge = self.captured_bridge_snapshot()?;
        let web_response = self.captured_web_response_snapshot()?;
        self.revalidate()?;
        let [_, outer_ca, inner_ca, _] = public;
        Ok(CapturedCryptoPayload {
            outer_ca,
            inner_ca,
            certificate: certificate.to_vec(),
            private_key,
            bridge,
            web_response,
        })
    }
    pub(crate) fn bundle_path(&self) -> &Path {
        &self.bundle
    }
    pub(crate) fn identity_path(&self) -> &Path {
        &self.identity_path
    }
    /// These are live paths, not captured byte snapshots. The actual portable
    /// synchronous bundle/device validator must execute inside this bracket,
    /// including its error paths. Async renewal/ACK bootstrap requires a
    /// separate admitted successor generation and never this old capture lease.
    pub fn with_portable_paths<T>(
        &mut self,
        validate: impl FnOnce(&Path, &Path) -> io::Result<T>,
    ) -> io::Result<T> {
        self.revalidate()?;
        let result = validate(&self.bundle, &self.identity_path);
        self.revalidate()?;
        result
    }
}

/// B-06 S23: what the provider's renewal step holds before a session's
/// capture. The same signed authority, container, Aegis tree, bundle
/// directory, four public files and bridge state as `CapturedAppGroupInputs`
/// (and the same provider tree lease, so no import or forget runs beside it),
/// but neither the identity payload files nor the journal-absent check: the
/// renewal step itself opens the protected Store, which holds `.lock`, and
/// writes the online journal. Its own writes change the identity directory's
/// mtime, so that one directory is revalidated by inode, owner and mode only.
/// Nothing here admits an identity, dials anything or grants capture; a
/// session still captures its own fresh `CapturedAppGroupInputs` afterwards.
pub(crate) struct CapturedRenewalInputs {
    authority: CaptureAuthority,
    container: HeldContainer,
    root: HeldDirectory,
    identity: HeldDirectory,
    bundle_directory: HeldDirectory,
    public: HeldPublicFiles,
    bridge: CapturedBridgeState,
    bundle: PathBuf,
    identity_path: PathBuf,
    _lease: Option<TreeLease>,
}
impl CapturedRenewalInputs {
    /// Provider renewal capture under the provider tree lease.
    pub(crate) fn capture_claim(group: &str) -> io::Result<Self> {
        let lease = PROVIDER_TREE_GATE.lease();
        Self::capture_from_authority(
            CaptureAuthority::Signed(CurrentCodeAppGroupClaim::capture(group)?),
            Some(lease),
        )
    }

    /// Unsigned lib-test capture of `dir/Aegis`, as `capture_test_root`.
    #[cfg(test)]
    pub(crate) fn capture_test_root(dir: &Path) -> io::Result<Self> {
        if canonical_container(dir)? != dir {
            return Err(refused());
        }
        Self::capture_from_authority(
            CaptureAuthority::TestRoot {
                container: dir.to_owned(),
                uid: unsafe { libc::geteuid() },
            },
            None,
        )
    }

    fn capture_from_authority(
        authority: CaptureAuthority,
        lease: Option<TreeLease>,
    ) -> io::Result<Self> {
        let uid = authority.uid();
        let container = HeldContainer::open(authority.container(), uid)?;
        let root = HeldDirectory::open(container.file(), std::ffi::OsStr::new("Aegis"), uid, true)?;
        let identity =
            HeldDirectory::open(&root.file, std::ffi::OsStr::new("identity"), uid, true)?;
        let bundle_directory =
            HeldDirectory::open(&root.file, std::ffi::OsStr::new("bundle"), uid, true)?;
        let public = HeldPublicFiles::open(&bundle_directory.file, uid)?;
        let bundle = authority.container().join("Aegis/bundle");
        let identity_path = authority.container().join("Aegis/identity");
        let bridge = CapturedBridgeState::capture(&identity, &identity_path, uid)?;
        let owner = Self {
            authority,
            container,
            root,
            identity,
            bundle_directory,
            public,
            bridge,
            bundle,
            identity_path,
            _lease: lease,
        };
        owner.revalidate()?;
        Ok(owner)
    }

    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.authority.revalidate()?;
        self.container.revalidate()?;
        self.root.revalidate()?;
        self.identity.revalidate_named_inode()?;
        self.bundle_directory.revalidate()?;
        self.public.revalidate()?;
        self.bridge.revalidate(&self.identity)?;
        Ok(())
    }

    /// The four public members through the held descriptors.
    pub(crate) fn public_payload(&mut self) -> io::Result<[Vec<u8>; 4]> {
        self.revalidate()?;
        let payload = self.public.read()?;
        self.revalidate()?;
        Ok(payload)
    }

    pub(crate) fn bridge_snapshot(&self) -> io::Result<Option<CapturedBridgeSnapshot>> {
        self.revalidate()?;
        Ok(match &self.bridge {
            CapturedBridgeState::Absent => None,
            CapturedBridgeState::Present(bridge) => Some(bridge.snapshot()),
        })
    }

    pub(crate) fn bundle_path(&self) -> &Path {
        &self.bundle
    }

    pub(crate) fn identity_path(&self) -> &Path {
        &self.identity_path
    }

    /// Run `step` over the live identity directory path, bracketed by
    /// revalidation of every held descriptor.
    pub(crate) fn with_identity_path<T>(&mut self, step: impl FnOnce(&Path) -> T) -> io::Result<T> {
        self.revalidate()?;
        let result = step(&self.identity_path);
        self.revalidate()?;
        Ok(result)
    }
}

/// The provider's own signed claim: its canonical App Group container and
/// euid, for an identity import or forget (S14). The same code signature,
/// entitlement and container observation as a capture; no descriptor of the
/// tree is opened here.
pub(crate) fn signed_provider_container() -> io::Result<(PathBuf, u32)> {
    let claim = CurrentCodeAppGroupClaim::capture(PROVIDER_APP_GROUP)?;
    Ok((claim.container, claim.uid))
}

/// The containing host has a different exact signed role from the provider.
/// It may prepare a runtime record only over an existing private Aegis tree;
/// this capture never manufactures identity or profile files.
pub(crate) struct CapturedHostAppGroupInputs {
    authority: CurrentCodeAppGroupClaim,
    container: HeldContainer,
    root: HeldDirectory,
    identity: HeldDirectory,
    bundle_directory: HeldDirectory,
    public: HeldPublicFiles,
    identity_files: HeldIdentityFiles,
    bundle: PathBuf,
    identity_path: PathBuf,
}

impl CapturedHostAppGroupInputs {
    pub(crate) fn capture_claim() -> io::Result<Self> {
        let authority = CurrentCodeAppGroupClaim::capture_host(PROVIDER_APP_GROUP)?;
        let uid = authority.uid;
        let container = HeldContainer::open(&authority.container, uid)?;
        let root = HeldDirectory::open(container.file(), std::ffi::OsStr::new("Aegis"), uid, true)?;
        let identity =
            HeldDirectory::open(&root.file, std::ffi::OsStr::new("identity"), uid, true)?;
        let bundle_directory =
            HeldDirectory::open(&root.file, std::ffi::OsStr::new("bundle"), uid, true)?;
        let public = HeldPublicFiles::open(&bundle_directory.file, uid)?;
        let identity_files = HeldIdentityFiles::open(&identity.file, uid)?;
        let bundle = authority.container.join("Aegis/bundle");
        let identity_path = authority.container.join("Aegis/identity");
        let owner = Self {
            authority,
            container,
            root,
            identity,
            bundle_directory,
            public,
            identity_files,
            bundle,
            identity_path,
        };
        owner.revalidate()?;
        Ok(owner)
    }

    fn revalidate_except_owned_root_mtime(&self) -> io::Result<()> {
        self.authority.revalidate()?;
        self.container.revalidate()?;
        self.root.revalidate_named_inode()?;
        self.identity.revalidate()?;
        self.bundle_directory.revalidate()?;
        self.public.revalidate()?;
        self.identity_files.revalidate()?;
        Ok(())
    }
    pub(crate) fn revalidate(&self) -> io::Result<()> {
        self.revalidate_except_owned_root_mtime()?;
        self.root.revalidate()
    }
    pub(crate) fn bundle_path(&self) -> PathBuf {
        self.bundle.clone()
    }
    pub(crate) fn with_portable_paths<T>(
        &mut self,
        validate: impl FnOnce(&Path, &Path) -> io::Result<T>,
    ) -> io::Result<T> {
        self.revalidate()?;
        let result = validate(&self.bundle, &self.identity_path);
        self.revalidate()?;
        result
    }
    /// Publish only after a typed manager reload has been checked by the
    /// caller. The closure must repeat the held Store/profile issuance check
    /// just before the rename. Any post-rename failure is reported, never
    /// reclassified as a committed success.
    pub(crate) fn publish_runtime(
        &mut self,
        bytes: &[u8],
        mut recheck_identity: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        self.revalidate()?;
        recheck_identity()?;
        atomic_publish_runtime(&self.root.file, self.authority.uid, bytes, || {
            self.revalidate_except_owned_root_mtime()?;
            recheck_identity()?;
            self.revalidate_except_owned_root_mtime()
        })?;
        self.root.refresh_after_owned_mutation()?;
        self.revalidate()?;
        recheck_identity()?;
        self.revalidate()
    }
}

struct RuntimeTemp<'a> {
    parent: &'a File,
    name: CString,
    dev: u64,
    ino: u64,
    active: bool,
}
impl Drop for RuntimeTemp<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let raw = unsafe {
            libc::openat(
                self.parent.as_raw_fd(),
                self.name.as_ptr(),
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if let Ok(file) = owned(raw) {
            if let Ok(generation) = generation(&file) {
                if generation.dev == self.dev && generation.ino == self.ino {
                    unsafe {
                        libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0);
                    }
                }
            }
        }
    }
}

fn runtime_leaf(parent: &File, uid: u32) -> io::Result<Option<File>> {
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            c"runtime.json".as_ptr(),
            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(None);
        }
        return Err(refused());
    }
    let file = owned(raw)?;
    let g = generation(&file)?;
    if g.uid != uid
        || g.mode != (libc::S_IFREG as u32 | 0o600)
        || g.links != 1
        || g.size < 0
        || g.size as u64 > MAX_RUNTIME_FILE
    {
        return Err(refused());
    }
    Ok(Some(file))
}

fn atomic_publish_runtime(
    parent: &File,
    uid: u32,
    bytes: &[u8],
    before_rename: impl FnOnce() -> io::Result<()>,
) -> io::Result<()> {
    if bytes.is_empty() || bytes.len() as u64 > MAX_RUNTIME_FILE {
        return Err(refused());
    }
    // Reject an unsafe current leaf before replacing it. renameat itself does
    // not follow an intervening symlink, and post-rename inode/byte checks
    // establish which file was actually published.
    runtime_leaf(parent, uid)?;
    let mut created = None;
    for _ in 0..3 {
        let sequence = RUNTIME_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = CString::new(format!(
            ".runtime.json.tmp.{}.{}",
            std::process::id(),
            sequence
        ))
        .map_err(|_| refused())?;
        let raw = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if raw >= 0 {
            created = Some((name, owned(raw)?));
            break;
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST) {
            return Err(refused());
        }
    }
    let (name, mut file) = created.ok_or_else(refused)?;
    let g = generation(&file)?;
    let mut guard = RuntimeTemp {
        parent,
        name,
        dev: g.dev,
        ino: g.ino,
        active: true,
    };
    if g.uid != uid || g.mode != (libc::S_IFREG as u32 | 0o600) || g.links != 1 {
        return Err(refused());
    }
    file.write_all(bytes).map_err(|_| refused())?;
    file.sync_all().map_err(|_| refused())?;
    before_rename()?;
    runtime_leaf(parent, uid)?;
    if unsafe {
        libc::renameat(
            parent.as_raw_fd(),
            guard.name.as_ptr(),
            parent.as_raw_fd(),
            c"runtime.json".as_ptr(),
        )
    } != 0
    {
        return Err(refused());
    }
    guard.active = false;
    parent.sync_all().map_err(|_| refused())?;
    let named = runtime_leaf(parent, uid)?.ok_or_else(refused)?;
    let named_generation = generation(&named)?;
    if named_generation.dev != guard.dev
        || named_generation.ino != guard.ino
        || named_generation.size != bytes.len() as i64
    {
        return Err(refused());
    }
    let mut observed = Vec::new();
    named
        .take(MAX_RUNTIME_FILE + 1)
        .read_to_end(&mut observed)
        .map_err(|_| refused())?;
    if observed != bytes {
        return Err(refused());
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    #[test]
    fn private_reader_preallocates_for_short_read_and_refuses_overlimit() {
        let base = std::env::temp_dir().join(format!(
            "aegis-private-reader-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = base.join("credential");
        std::fs::write(&path, [b'a'; 64]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let parent = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let held = HeldPrivateFile::open(&parent, "credential", uid).unwrap();
        let secret = held.read_bounded_private(65).unwrap();
        assert_eq!(secret.len(), 64);
        assert!(secret.capacity() >= 65);
        assert!(secret.iter().all(|byte| *byte == b'a'));
        drop(secret);
        drop(held);
        std::fs::write(&path, [b'b'; 66]).unwrap();
        let held = HeldPrivateFile::open(&parent, "credential", uid).unwrap();
        assert_eq!(
            held.read_bounded_private(65).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(held);
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn captured_bridge_retains_sidecar_and_credential_generation() {
        let base = std::env::temp_dir().join(format!(
            "aegis-held-bridge-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let identity_path = base.join("identity");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&identity_path).unwrap();
        for path in [&base, &identity_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let parent = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let identity =
            HeldDirectory::open(&parent, std::ffi::OsStr::new("identity"), uid, true).unwrap();
        let absent = CapturedBridgeState::capture(&identity, &identity_path, uid).unwrap();
        absent.revalidate(&identity).unwrap();
        let settings = BridgeSettings {
            authority: "relay.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: identity_path.join("bridge-credential"),
        };
        let sidecar = identity_path.join(SIDECAR);
        std::fs::write(&sidecar, toml::to_string(&settings).unwrap()).unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(absent.revalidate(&identity).is_err());
        // The configured credential leaf is reported, never named.
        let missing = CapturedBridgeState::capture(&identity, &identity_path, uid)
            .err()
            .unwrap();
        assert_eq!(custody_refusal_code(&missing), CREDENTIAL_MISSING);
        let credential_path = identity_path.join("bridge-credential");
        std::fs::write(&credential_path, [b'a'; 64]).unwrap();
        std::fs::set_permissions(&credential_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let captured = CapturedBridgeState::capture(&identity, &identity_path, uid).unwrap();
        captured.revalidate(&identity).unwrap();
        let snapshot = match &captured {
            CapturedBridgeState::Present(bridge) => bridge.snapshot(),
            CapturedBridgeState::Absent => panic!("bridge capture unexpectedly absent"),
        };
        assert!(snapshot.secret.iter().all(|b| *b == b'a'));
        std::fs::write(&credential_path, [b'b'; 64]).unwrap();
        assert!(captured.revalidate(&identity).is_err());
        assert!(snapshot.secret.iter().all(|b| *b == b'a'));
        drop(captured);
        let captured = CapturedBridgeState::capture(&identity, &identity_path, uid).unwrap();
        std::fs::rename(&sidecar, identity_path.join("moved-sidecar")).unwrap();
        std::fs::write(&sidecar, toml::to_string(&settings).unwrap()).unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(captured.revalidate(&identity).is_err());
        drop(captured);
        let mut outside = settings;
        outside.credential_file = base.join("external-credential");
        std::fs::write(&sidecar, toml::to_string(&outside).unwrap()).unwrap();
        assert!(CapturedBridgeState::capture(&identity, &identity_path, uid).is_err());
        outside.credential_file = identity_path.join("DEVICE.KEY");
        let alias = identity_path.join("DEVICE.KEY");
        std::fs::write(&alias, [b'c'; 64]).unwrap();
        std::fs::set_permissions(&alias, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&sidecar, toml::to_string(&outside).unwrap()).unwrap();
        assert!(CapturedBridgeState::capture(&identity, &identity_path, uid).is_err());
        outside.credential_file = credential_path.clone();
        std::fs::write(&sidecar, toml::to_string(&outside).unwrap()).unwrap();
        std::fs::write(&credential_path, [b'd'; 66]).unwrap();
        assert!(CapturedBridgeState::capture(&identity, &identity_path, uid).is_err());
        std::fs::rename(&sidecar, identity_path.join("second-moved-sidecar")).unwrap();
        symlink(identity_path.join("second-moved-sidecar"), &sidecar).unwrap();
        assert!(CapturedBridgeState::capture(&identity, &identity_path, uid).is_err());
        drop(identity);
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn captured_web_response_retains_sidecar_and_key_generation() {
        use std::os::unix::fs::PermissionsExt;
        let base = std::env::temp_dir().join(format!(
            "aegis-held-web-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let identity_path = base.join("identity");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&identity_path).unwrap();
        for path in [&base, &identity_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let parent = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let identity =
            HeldDirectory::open(&parent, std::ffi::OsStr::new("identity"), uid, true).unwrap();
        let absent = CapturedWebResponseState::capture(&identity, &identity_path, uid).unwrap();
        absent.revalidate(&identity).unwrap();
        let settings = WebResponseSettings {
            authority: "web.test".into(),
            descriptor_path: "/descriptor".into(),
            allowed_ingress_ips: vec!["192.0.2.4".parse().unwrap()],
            credential_file: identity_path.join("web.key"),
        };
        let sidecar = identity_path.join(aegis_client::device_web_response::SIDECAR);
        std::fs::write(&sidecar, toml::to_string(&settings).unwrap()).unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(absent.revalidate(&identity).is_err());
        assert!(CapturedWebResponseState::capture(&identity, &identity_path, uid).is_err());
        let key = identity_path.join("web.key");
        std::fs::write(&key, [b'a'; 64]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let captured = CapturedWebResponseState::capture(&identity, &identity_path, uid).unwrap();
        let snapshot = match &captured {
            CapturedWebResponseState::Present(web) => web.snapshot(),
            CapturedWebResponseState::Absent => panic!("web sidecar unexpectedly absent"),
        };
        assert_eq!(snapshot.settings, settings);
        assert!(snapshot.secret.iter().all(|b| *b == b'a'));
        std::fs::write(&key, [b'b'; 64]).unwrap();
        assert!(captured.revalidate(&identity).is_err());
        assert!(snapshot.secret.iter().all(|b| *b == b'a'));
        drop(captured);
        std::fs::write(&key, [b'a'; 64]).unwrap();
        let captured = CapturedWebResponseState::capture(&identity, &identity_path, uid).unwrap();
        std::fs::rename(&sidecar, identity_path.join("moved-web-sidecar")).unwrap();
        std::fs::write(&sidecar, toml::to_string(&settings).unwrap()).unwrap();
        std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(captured.revalidate(&identity).is_err());
        drop(captured);
        drop(identity);
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn absent_sfu_sidecar_refuses_orphan_broker_key() {
        let base = std::env::temp_dir().join(format!(
            "aegis-held-sfu-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let identity_path = base.join("identity");
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(&identity_path).unwrap();
        for path in [&base, &identity_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let parent = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let identity =
            HeldDirectory::open(&parent, std::ffi::OsStr::new("identity"), uid, true).unwrap();
        let absent = CapturedSfuState::capture(&identity, &identity_path, uid).unwrap();
        absent.revalidate(&identity).unwrap();
        let key = identity_path.join(crate::sfu_media_custody::BROKER_KEY);
        std::fs::write(&key, [b'a'; 64]).unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(absent.revalidate(&identity).is_err());
        drop((absent, identity, parent));
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn captured_bridge_accepts_reported_spelling_of_the_held_identity_only() {
        let name = format!(
            "aegis-held-bridge-alias-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let base = std::env::temp_dir().canonicalize().unwrap().join(&name);
        let identity_path = base.join("identity");
        let other = base.join("other");
        for dir in [&base, &identity_path, &other] {
            std::fs::create_dir(dir).unwrap();
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let parent = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let identity =
            HeldDirectory::open(&parent, std::ffi::OsStr::new("identity"), uid, true).unwrap();
        for dir in [&identity_path, &other] {
            let credential = dir.join("bridge-credential");
            std::fs::write(&credential, [b'a'; 64]).unwrap();
            std::fs::set_permissions(&credential, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let sidecar = identity_path.join(SIDECAR);
        let write_sidecar = |credential_file: PathBuf| {
            let settings = BridgeSettings {
                authority: "relay.test".into(),
                path: "/private/stream".into(),
                enrollment_path: "/private/enroll".into(),
                credential_file,
            };
            std::fs::write(&sidecar, toml::to_string(&settings).unwrap()).unwrap();
            std::fs::set_permissions(&sidecar, std::fs::Permissions::from_mode(0o600)).unwrap();
        };
        symlink("identity", base.join("alias")).unwrap();
        symlink("other", base.join("elsewhere")).unwrap();
        // The /var spelling of a /private/var temp dir is the same relation
        // NSFileManager's reported container has to the canonical one.
        let mut spellings = vec![base.join("alias")];
        let reported = std::env::temp_dir().join(&name).join("identity");
        if reported != identity_path {
            spellings.push(reported);
        }
        for spelling in spellings {
            write_sidecar(spelling.join("bridge-credential"));
            let captured = CapturedBridgeState::capture(&identity, &identity_path, uid).unwrap();
            captured.revalidate(&identity).unwrap();
            let CapturedBridgeState::Present(bridge) = &captured else {
                panic!("bridge capture unexpectedly absent");
            };
            assert_eq!(
                bridge.snapshot().settings.credential_file,
                identity_path.join("bridge-credential")
            );
        }
        for refused_file in [
            base.join("elsewhere/bridge-credential"),
            base.join("alias/absent/bridge-credential"),
            base.join("alias/DEVICE.KEY"),
            other.join("bridge-credential"),
        ] {
            write_sidecar(refused_file.clone());
            assert!(
                CapturedBridgeState::capture(&identity, &identity_path, uid).is_err(),
                "{refused_file:?}"
            );
        }
        drop(identity);
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn held_public_digest_refuses_in_place_mutation_and_leaf_replacement() {
        let base = std::env::temp_dir().join(format!(
            "aegis-held-public-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let leaves = [
            "bundle.json",
            "outer-ca.pem",
            "inner-ca.pem",
            "device-ca.pem",
        ];
        for (leaf, byte) in leaves.into_iter().zip(*b"abcd") {
            let path = base.join(leaf);
            std::fs::write(&path, [byte]).unwrap();
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(leaves, MEMBERS);
        let mut held = HeldPublicFiles::open(&parent, uid).unwrap();
        let digest = held.digest().unwrap();
        assert_eq!(digest, held.digest().unwrap());
        assert_eq!(
            digest,
            profile_digest_bytes(&[b"a", b"b", b"c", b"d"].map(|m| m.to_vec()))
        );
        std::fs::write(base.join(leaves[1]), b"changed").unwrap();
        assert!(held.digest().is_err());
        drop(held);
        let mut held = HeldPublicFiles::open(&parent, uid).unwrap();
        std::fs::rename(base.join(leaves[2]), base.join("moved")).unwrap();
        std::fs::write(base.join(leaves[2]), b"replacement").unwrap();
        std::fs::set_permissions(base.join(leaves[2]), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        assert!(held.digest().is_err());
        drop(held);
        drop(parent);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn exact_provider_role_rejects_wrong_application_or_entitlement() {
        let team = APPROVED_TEAM_ID;
        let provider = "TEAMID0000.dev.aegis.macos.PacketTunnel";
        assert!(exact_provider_role(team, provider, true));
        assert!(!exact_provider_role(team, provider, false));
        assert!(!exact_provider_role(
            team,
            "TEAMID0000.dev.aegis.macos",
            true
        ));
        assert!(!exact_provider_role(
            team,
            "TEAMID0000.dev.aegis.macos.OtherTunnel",
            true
        ));
        assert!(!exact_provider_role("OTHER12345", provider, true));
        assert!(!exact_provider_role("abcde12345", provider, true));
        assert!(!exact_provider_role(
            "ABCDE12345",
            "ABCDE12345.dev.aegis.macos.PacketTunnel",
            true
        ));
        assert!(CurrentCodeAppGroupClaim::capture("group.OTHER12345.dev.aegis.macos").is_err());
    }
    #[test]
    fn exact_host_role_is_distinct_from_provider_role() {
        let host = "TEAMID0000.dev.aegis.macos";
        let provider = "TEAMID0000.dev.aegis.macos.PacketTunnel";
        assert!(exact_host_role(APPROVED_TEAM_ID, host, true));
        assert!(!exact_host_role(APPROVED_TEAM_ID, provider, true));
        assert!(!exact_provider_role(APPROVED_TEAM_ID, host, true));
        assert!(!exact_host_role(APPROVED_TEAM_ID, host, false));
        assert!(!exact_host_role("OTHER12345", host, true));
        assert!(
            CurrentCodeAppGroupClaim::capture_host("group.OTHER12345.dev.aegis.macos").is_err()
        );
    }
    #[test]
    fn observation_child_role_is_exact_and_has_no_provider_entitlement() {
        let child = "TEAMID0000.dev.aegis.macos.ObserveChild";
        let provider = "TEAMID0000.dev.aegis.macos.PacketTunnel";
        let host = "TEAMID0000.dev.aegis.macos";
        assert!(exact_observation_child_role(APPROVED_TEAM_ID, child, false));
        for (team, app, has_ne) in [
            (APPROVED_TEAM_ID, child, true),
            (APPROVED_TEAM_ID, provider, false),
            (APPROVED_TEAM_ID, host, false),
            ("OTHER12345", child, false),
            (
                APPROVED_TEAM_ID,
                "TEAMID0000.dev.aegis.macos.ObserveHelper",
                false,
            ),
        ] {
            assert!(!exact_observation_child_role(team, app, has_ne));
        }
        assert!(
            CapturedObservationChildClaim::capture("group.OTHER12345.dev.aegis.macos").is_err()
        );
    }
    #[test]
    fn atomic_runtime_publication_replaces_only_after_checked_commit() {
        let base = std::env::temp_dir().join(format!(
            "aegis-appgroup-runtime-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let first = br#"{"schema":"fixture-1"}"#;
        atomic_publish_runtime(&dir, uid, first, || Ok(())).unwrap();
        assert_eq!(std::fs::read(base.join("runtime.json")).unwrap(), first);
        let before = generation(&runtime_leaf(&dir, uid).unwrap().unwrap()).unwrap();
        let refused = atomic_publish_runtime(&dir, uid, br#"{"schema":"fixture-2"}"#, || {
            Err(io::ErrorKind::PermissionDenied.into())
        });
        assert!(refused.is_err());
        assert_eq!(std::fs::read(base.join("runtime.json")).unwrap(), first);
        assert!(generation(&runtime_leaf(&dir, uid).unwrap().unwrap()).unwrap() == before);
        assert_eq!(std::fs::read_dir(&base).unwrap().count(), 1);
        let second = br#"{"schema":"fixture-2"}"#;
        atomic_publish_runtime(&dir, uid, second, || Ok(())).unwrap();
        assert_eq!(std::fs::read(base.join("runtime.json")).unwrap(), second);
        assert_ne!(
            generation(&runtime_leaf(&dir, uid).unwrap().unwrap())
                .unwrap()
                .ino,
            before.ino
        );
        drop(dir);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn atomic_runtime_publication_rejects_unsafe_existing_leaf() {
        let base = std::env::temp_dir().join(format!(
            "aegis-appgroup-runtime-unsafe-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let target = base.join("target");
        std::fs::write(&target, b"inert").unwrap();
        std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, base.join("runtime.json")).unwrap();
        assert!(atomic_publish_runtime(&dir, uid, b"new", || Ok(())).is_err());
        std::fs::remove_file(base.join("runtime.json")).unwrap();
        std::fs::hard_link(&target, base.join("runtime.json")).unwrap();
        assert!(atomic_publish_runtime(&dir, uid, b"new", || Ok(())).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"inert");
        drop(dir);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn held_root_refreshes_only_after_owned_runtime_mutation() {
        let base = std::env::temp_dir().join(format!(
            "aegis-appgroup-runtime-root-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let parent = File::open(base.parent().unwrap()).unwrap();
        let uid = unsafe { libc::geteuid() };
        let mut held = HeldDirectory::open(&parent, base.file_name().unwrap(), uid, true).unwrap();
        atomic_publish_runtime(&held.file, uid, b"inert runtime", || Ok(())).unwrap();
        held.revalidate_named_inode().unwrap();
        held.refresh_after_owned_mutation().unwrap();
        held.revalidate().unwrap();
        std::fs::rename(&base, base.with_extension("detached")).unwrap();
        assert!(held.refresh_after_owned_mutation().is_err());
        drop(held);
        drop(parent);
        std::fs::remove_dir_all(base.with_extension("detached")).unwrap();
    }
    #[test]
    fn actual_callback_error_still_revalidates_and_custody_failure_takes_precedence() {
        let base = std::env::temp_dir().join(format!(
            "aegis-appgroup-error-fd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = base.join("record");
        std::fs::write(&path, b"never-issued original fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let dir = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let mut held = HeldPrivateFile::open(&dir, "record", uid).unwrap();
        let unchanged = held
            .with_file::<()>(|_| {
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "fixture callback failed",
                ))
            })
            .unwrap_err();
        assert_eq!(unchanged.kind(), io::ErrorKind::WouldBlock);
        let changed = held
            .with_file::<()>(|_| {
                std::fs::write(&path, b"changed fixture generation")?;
                Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "fixture callback failed",
                ))
            })
            .unwrap_err();
        assert_eq!(changed.kind(), io::ErrorKind::PermissionDenied);
        assert!(held.revalidate().is_err());
        drop(held);
        drop(dir);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn held_identity_lock_accepts_same_inode_and_refuses_replacement_or_symlink() {
        use std::io::Write;
        let base = std::env::temp_dir().join(format!(
            "aegis-appgroup-identity-lock-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = base.join(".lock");
        let mut lock = File::create(&path).unwrap();
        lock.write_all(b"inert lock fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        lock.try_lock().unwrap();
        let dir = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let held = HeldPrivateFile::open(&dir, ".lock", uid).unwrap();
        // Holding the same Store-style lock does not itself invalidate custody.
        held.revalidate().unwrap();
        std::fs::rename(&path, base.join("former-lock")).unwrap();
        std::fs::write(&path, b"inert lock fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            held.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        std::fs::remove_file(&path).unwrap();
        symlink(base.join("former-lock"), &path).unwrap();
        assert!(HeldPrivateFile::open(&dir, ".lock", uid).is_err());
        drop(held);
        drop(dir);
        drop(lock);
        std::fs::remove_dir_all(base).unwrap();
    }
    #[test]
    fn app_group_test_root_keeps_descriptor_custody() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        let mut inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        inputs.revalidate().unwrap();
        assert_eq!(
            inputs.captured_public_profile_digest().unwrap(),
            tree.profile_sha256()
        );
        assert!(inputs.captured_bridge_snapshot().unwrap().is_none());
        // The shared temp parent is above the container and is not held: a
        // sibling of the container changes its mtime but must not invalidate
        // capture.
        let sibling = tree.root().with_extension("sibling");
        std::fs::create_dir(&sibling).unwrap();
        inputs.revalidate().unwrap();
        std::fs::remove_dir(&sibling).unwrap();
        let record = tree.identity_dir().join("identity.json");
        let bytes = std::fs::read(&record).unwrap();
        std::fs::rename(&record, tree.identity_dir().join("moved.json")).unwrap();
        std::fs::write(&record, &bytes).unwrap();
        std::fs::set_permissions(&record, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            inputs.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(inputs);
        // Capture after the replacement sees the new leaf; then refuse a
        // group-readable private directory. No runtime record is required.
        CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let bundle = tree.root().join("Aegis/bundle");
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o750)).unwrap();
        assert!(CapturedAppGroupInputs::capture_test_root(tree.root()).is_err());
        std::fs::set_permissions(&bundle, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!tree.root().join("Aegis/runtime.json").exists());
        CapturedAppGroupInputs::capture_test_root(tree.root())
            .unwrap()
            .revalidate()
            .unwrap();
    }

    #[test]
    fn app_group_capture_ignores_stale_runtime_record_and_refuses_late_tree_change() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        let runtime = tree.root().join("Aegis/runtime.json");
        // A stale record of any shape (garbage, unsafe mode, symlink) present
        // before capture is never opened: capture and revalidation succeed.
        std::fs::write(&runtime, b"{\"schema\":\"stale\"}").unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o666)).unwrap();
        let mut inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        inputs.revalidate().unwrap();
        // Rewriting it in place does not touch any held generation.
        std::fs::write(&runtime, b"not json").unwrap();
        inputs.revalidate().unwrap();
        assert_eq!(
            inputs.captured_public_profile_digest().unwrap(),
            tree.profile_sha256()
        );
        drop(inputs);
        std::fs::remove_file(&runtime).unwrap();
        symlink(tree.root().join("Aegis/identity/device.key"), &runtime).unwrap();
        let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        inputs.revalidate().unwrap();
        // Removing it, or creating one after capture, changes the held Aegis
        // directory generation: the claim is refused, never re-read.
        std::fs::remove_file(&runtime).unwrap();
        assert_eq!(
            inputs.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        drop(inputs);
        let inputs = CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        inputs.revalidate().unwrap();
        std::fs::write(&runtime, b"{}").unwrap();
        assert_eq!(
            inputs.revalidate().unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn app_group_test_root_requires_canonical_absolute_dir() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        let alias = tree.root().with_extension("alias");
        symlink(tree.root(), &alias).unwrap();
        assert!(CapturedAppGroupInputs::capture_test_root(&alias).is_err());
        std::fs::remove_file(&alias).unwrap();
        let dotted = tree.root().join("Aegis/..");
        assert!(CapturedAppGroupInputs::capture_test_root(&dotted).is_err());
        let relative = Path::new(tree.root().file_name().unwrap());
        assert!(CapturedAppGroupInputs::capture_test_root(relative).is_err());
        // The uncanonicalized /var/folders spelling resolves through /var.
        let spelled = std::env::temp_dir().join(tree.root().file_name().unwrap());
        if spelled != tree.root() {
            assert!(CapturedAppGroupInputs::capture_test_root(&spelled).is_err());
        }
        CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
    }

    fn container_errno(error: &io::Error) -> Option<i32> {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<CustodyContainerErrno>())
            .map(|code| code.0)
    }

    #[test]
    fn app_group_custody_errno_names_only_a_carried_errno() {
        let wrapped = |inner: Box<dyn std::error::Error + Send + Sync>| {
            io::Error::new(io::ErrorKind::PermissionDenied, inner)
        };
        let open = wrapped(Box::new(CustodyContainerErrno(libc::EMFILE)));
        assert_eq!(custody_errno(&open), Some(libc::EMFILE));
        let ancestor = wrapped(Box::new(CustodyContainerAncestorErrno(libc::ENFILE)));
        assert_eq!(custody_errno(&ancestor), Some(libc::ENFILE));
        let raw = io::Error::from_raw_os_error(libc::ENOMEM);
        assert_eq!(custody_errno(&raw), Some(libc::ENOMEM));
        // Opaque and coded refusals carry none.
        assert_eq!(custody_errno(&refused()), None);
        assert_eq!(custody_errno(&custody_code(AEGIS_TREE_MISSING)), None);
        assert_eq!(custody_errno(&container_unresolved()), None);
    }

    #[test]
    fn app_group_canonical_container_resolves_var_prefix_to_real_directories() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        let uid = unsafe { libc::geteuid() };
        assert_eq!(canonical_container(tree.root()).unwrap(), tree.root());
        // NSFileManager spells a root extension's container through /var.
        if let Ok(rest) = tree.root().strip_prefix("/private/var") {
            let spelled = Path::new("/var").join(rest);
            let canonical = canonical_container(&spelled).unwrap();
            assert_eq!(canonical, tree.root());
            // The anchor refuses the symlinked spelling: /var is not a real
            // directory, and a descriptor opened through it names /private.
            let error = HeldContainer::open(&spelled, uid).err().unwrap();
            assert_eq!(
                custody_refusal_code(&error),
                CUSTODY_CONTAINER_ANCESTOR_REFUSED
            );
            assert_eq!(
                open_container_anchor(&spelled).err(),
                Some(ContainerAnchorFailure::Mismatch)
            );
            HeldContainer::open(&canonical, uid)
                .unwrap()
                .revalidate()
                .unwrap();
        }
        let leaf = tree.root().join("Aegis/identity/identity.json");
        for refused_path in [
            leaf.as_path(),
            Path::new("relative/container"),
            Path::new("/private/../private/var"),
            Path::new("/"),
        ] {
            let resolved = canonical_container(refused_path);
            assert!(
                resolved.is_err() || HeldContainer::open(&resolved.unwrap(), uid).is_err(),
                "{refused_path:?}"
            );
        }
        assert!(canonical_container(&tree.root().join("absent")).is_err());
        assert_eq!(
            custody_refusal_code(&refused()),
            "provider_app_group_custody_refused"
        );
    }

    #[test]
    fn app_group_capture_sub_codes_name_container_tree_and_missing_leaf() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        let code = |root: &Path| {
            custody_refusal_code(
                &CapturedAppGroupInputs::capture_test_root(root)
                    .err()
                    .unwrap(),
            )
        };
        CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        let aegis = tree.root().join("Aegis");
        let mut leaves = vec![
            ("identity", aegis.join("identity")),
            ("bundle", aegis.join("bundle")),
        ];
        for member in MEMBERS {
            leaves.push((member, aegis.join("bundle").join(member)));
        }
        for leaf in [
            ".lock",
            "identity.json",
            "device.key",
            "device.pem",
            "device-ca.pem",
            "bundle-profile.sha256",
        ] {
            leaves.push((leaf, aegis.join("identity").join(leaf)));
        }
        for (leaf, path) in &leaves {
            let aside = path.with_extension("aside");
            std::fs::rename(path, &aside).unwrap();
            assert_eq!(code(tree.root()), format!("file_missing:{leaf}"), "{leaf}");
            std::fs::rename(&aside, path).unwrap();
            CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();
        }
        // A leaf present but refused for another reason stays opaque.
        let certificate = aegis.join("identity/device.pem");
        let aside = certificate.with_extension("aside");
        std::fs::rename(&certificate, &aside).unwrap();
        symlink(&aside, &certificate).unwrap();
        assert_eq!(code(tree.root()), "provider_app_group_custody_refused");
        std::fs::remove_file(&certificate).unwrap();
        std::fs::rename(&aside, &certificate).unwrap();
        // No runtime record is a tree leaf: its absence names nothing.
        assert!(!aegis.join("runtime.json").exists());
        CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();

        let moved = tree.root().join("Aegis.aside");
        std::fs::rename(&aegis, &moved).unwrap();
        assert_eq!(code(tree.root()), AEGIS_TREE_MISSING);
        std::fs::rename(&moved, &aegis).unwrap();
        CapturedAppGroupInputs::capture_test_root(tree.root()).unwrap();

        // An absent container leaf is unresolved, not a missing tree leaf.
        let uid = unsafe { libc::geteuid() };
        let error = HeldContainer::open(&tree.root().join("group.absent"), uid)
            .err()
            .unwrap();
        assert_eq!(custody_refusal_code(&error), CONTAINER_UNRESOLVED);
        assert_eq!(
            custody_refusal_code(&container_unresolved()),
            CONTAINER_UNRESOLVED
        );
        // The configured credential leaf is never named.
        assert_eq!(
            custody_refusal_code(&missing_refused(CREDENTIAL_MISSING, libc::ENOENT)),
            "file_missing:credential"
        );
        assert_eq!(
            custody_refusal_code(&missing_refused(CREDENTIAL_MISSING, libc::EACCES)),
            "provider_app_group_custody_refused"
        );
        assert_eq!(missing_code("credential.hex"), "file_missing:other");
    }

    /// Paths of every open descriptor of this process that lies under
    /// `base`. `base` is unique to one test, so parallel tests cannot add to
    /// it; the census proves which directories a capture actually holds.
    fn held_paths_under(base: &Path) -> Vec<PathBuf> {
        let limit = unsafe { libc::getdtablesize() }.clamp(0, 65_536);
        (0..limit)
            .filter_map(|fd| {
                let mut buffer = [0u8; libc::PATH_MAX as usize];
                if unsafe { libc::fcntl(fd, libc::F_GETPATH, buffer.as_mut_ptr()) } < 0 {
                    return None;
                }
                let end = buffer.iter().position(|b| *b == 0)?;
                let path = PathBuf::from(std::ffi::OsStr::from_bytes(&buffer[..end]));
                path.starts_with(base).then_some(path)
            })
            .collect()
    }

    fn private_test_base(label: &str) -> PathBuf {
        let base = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "aegis-appgroup-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        base
    }

    #[test]
    fn app_group_container_anchor_holds_nothing_above_and_keeps_full_generation() {
        use crate::test_fixture::ReadyTree;
        let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
        let base = private_test_base("anchor");
        let ancestor = base.join("ancestor");
        let container = ancestor.join("container");
        std::fs::create_dir(&ancestor).unwrap();
        // Only this test's private ancestors are mutated; the shared temp
        // parent is never chmod'ed or replaced.
        let mode = |path: &Path, bits: u32| {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(bits)).unwrap()
        };
        mode(&ancestor, 0o700);
        std::fs::rename(tree.root(), &container).unwrap();
        let code = |root: &Path| {
            custody_refusal_code(
                &CapturedAppGroupInputs::capture_test_root(root)
                    .err()
                    .unwrap(),
            )
        };

        // Nothing above the container is held: every descriptor the capture
        // opened under `base` is the container or lies below it, and the
        // container is held. Dropping the capture releases all of them.
        assert!(held_paths_under(&base).is_empty());
        let inputs = CapturedAppGroupInputs::capture_test_root(&container).unwrap();
        inputs.revalidate().unwrap();
        let held = held_paths_under(&base);
        assert!(
            held.iter().all(|path| path.starts_with(&container)),
            "{held:?}"
        );
        assert!(held.contains(&container), "{held:?}");
        assert!(
            !held.contains(&ancestor) && !held.contains(&base),
            "{held:?}"
        );
        assert!(held.contains(&container.join("Aegis/identity/device.key")));
        drop(inputs);
        assert!(held_paths_under(&base).is_empty());

        let inputs = CapturedAppGroupInputs::capture_test_root(&container).unwrap();
        // Another group container or a file beside ours leaves custody intact.
        std::fs::create_dir(ancestor.join("group.other")).unwrap();
        std::fs::write(base.join("cache"), b"inert").unwrap();
        inputs.revalidate().unwrap();
        std::fs::remove_dir(ancestor.join("group.other")).unwrap();
        std::fs::remove_file(base.join("cache")).unwrap();
        inputs.revalidate().unwrap();

        // A writable ancestor is refused by its own sub-code, at capture and
        // on revalidation; restoring the mode is accepted again.
        mode(&ancestor, 0o777);
        let error = inputs.revalidate().unwrap_err();
        assert_eq!(
            custody_refusal_code(&error),
            CUSTODY_CONTAINER_ANCESTOR_REFUSED
        );
        assert_eq!(code(&container), CUSTODY_CONTAINER_ANCESTOR_REFUSED);
        mode(&ancestor, 0o700);
        inputs.revalidate().unwrap();

        // A symlink in place of an ancestor is not a real directory. Without
        // that path check, the anchor itself still refuses the route: a
        // descriptor opened through the link names the real path.
        let real = base.join("ancestor.real");
        std::fs::rename(&ancestor, &real).unwrap();
        symlink("ancestor.real", &ancestor).unwrap();
        let error = inputs.revalidate().unwrap_err();
        assert_eq!(
            custody_refusal_code(&error),
            CUSTODY_CONTAINER_ANCESTOR_REFUSED
        );
        assert!(CapturedAppGroupInputs::capture_test_root(&container).is_err());
        let uid = unsafe { libc::geteuid() };
        let error = HeldContainer::open(&container, uid).err().unwrap();
        assert_eq!(
            custody_refusal_code(&error),
            CUSTODY_CONTAINER_ANCESTOR_REFUSED
        );
        assert_eq!(
            open_container_anchor(&container).err(),
            Some(ContainerAnchorFailure::Mismatch)
        );
        std::fs::remove_file(&ancestor).unwrap();
        std::fs::rename(&real, &ancestor).unwrap();
        inputs.revalidate().unwrap();

        // A different inode under the ancestor's name, with the same owner
        // and mode: the held container is intact under the former inode, but
        // the canonical path no longer names it.
        let former = base.join("ancestor.former");
        std::fs::rename(&ancestor, &former).unwrap();
        std::fs::create_dir(&ancestor).unwrap();
        mode(&ancestor, 0o700);
        let error = inputs.revalidate().unwrap_err();
        assert_eq!(custody_refusal_code(&error), CONTAINER_UNRESOLVED);
        // With a same-owner, same-mode container at the canonical path again,
        // only the fresh anchor's generation (dev/ino) differs from the held,
        // untouched one.
        std::fs::create_dir(&container).unwrap();
        mode(&container, 0o700);
        let error = inputs.revalidate().unwrap_err();
        assert_eq!(
            custody_refusal_code(&error),
            "provider_app_group_custody_refused"
        );
        std::fs::remove_dir(&container).unwrap();
        std::fs::remove_dir(&ancestor).unwrap();
        std::fs::rename(&former, &ancestor).unwrap();
        inputs.revalidate().unwrap();

        // A swapped container (a new directory at the canonical path) and a
        // symlinked one are refused.
        let moved = ancestor.join("container.moved");
        std::fs::rename(&container, &moved).unwrap();
        std::fs::create_dir(&container).unwrap();
        mode(&container, 0o700);
        assert!(inputs.revalidate().is_err());
        std::fs::remove_dir(&container).unwrap();
        symlink("container.moved", &container).unwrap();
        let error = inputs.revalidate().unwrap_err();
        assert_eq!(custody_refusal_code(&error), CUSTODY_CONTAINER_ERRNO);
        assert!(matches!(
            container_errno(&error),
            Some(libc::ELOOP | libc::ENOTDIR)
        ));
        assert!(CapturedAppGroupInputs::capture_test_root(&container).is_err());
        let error = HeldContainer::open(&container, uid).err().unwrap();
        assert_eq!(custody_refusal_code(&error), CUSTODY_CONTAINER_ERRNO);
        std::fs::remove_file(&container).unwrap();
        std::fs::rename(&moved, &container).unwrap();
        // Even the original directory renamed back is a new generation (its
        // ctime moved): a live capture never survives the container moving.
        assert!(inputs.revalidate().is_err());
        drop(inputs);

        // The container itself keeps the full generation check.
        let inputs = CapturedAppGroupInputs::capture_test_root(&container).unwrap();
        std::fs::create_dir(container.join("Library")).unwrap();
        assert!(inputs.revalidate().is_err());
        std::fs::remove_dir(container.join("Library")).unwrap();
        drop(inputs);

        // A container that other users can write is refused (opaque).
        mode(&container, 0o707);
        assert_eq!(code(&container), "provider_app_group_custody_refused");
        mode(&container, 0o700);

        if uid != 0 {
            // Ownership by another non-root uid is refused for the container
            // and for an ancestor alike.
            let held = HeldContainer::open(&container, uid).unwrap();
            assert!(admit_directory(&held.generation, uid, false).is_ok());
            assert!(admit_directory(&held.generation, uid + 1, false).is_err());
            assert!(admit_container_ancestors(&container, uid).is_ok());
            let error = admit_container_ancestors(&container, uid + 1).unwrap_err();
            assert_eq!(
                custody_refusal_code(&error),
                CUSTODY_CONTAINER_ANCESTOR_REFUSED
            );
            assert!(container_admitted(&held.file, uid));
            assert!(!container_admitted(&held.file, uid + 1));
            drop(held);

            // An ancestor that cannot be lstat'd (its parent is not
            // searchable) carries the lstat errno in its own sub-code, at
            // capture and on revalidation, never the policy refusal.
            let ancestor_errno = |error: &io::Error| {
                error
                    .get_ref()
                    .and_then(|inner| inner.downcast_ref::<CustodyContainerAncestorErrno>())
                    .map(|code| code.0)
            };
            let inputs = CapturedAppGroupInputs::capture_test_root(&container).unwrap();
            mode(&base, 0o600);
            let checks = container_ancestor_checks(&container, uid);
            let error = inputs.revalidate().unwrap_err();
            let opened = HeldContainer::open(&container, uid).err().unwrap();
            mode(&base, 0o700);
            assert!(checks.contains(&(
                ancestor.as_path(),
                Err(AncestorFailure::Lstat(libc::EACCES))
            )));
            assert!(checks.contains(&(base.as_path(), Ok(()))));
            for error in [&error, &opened] {
                assert_eq!(
                    custody_refusal_code(error),
                    CUSTODY_CONTAINER_ANCESTOR_ERRNO
                );
                assert_eq!(ancestor_errno(error), Some(libc::EACCES));
                assert_eq!(container_errno(error), None);
            }
            inputs.revalidate().unwrap();
            drop(inputs);

            // No ancestor is opened: a search-only ancestor still captures.
            mode(&ancestor, 0o100);
            let inputs = CapturedAppGroupInputs::capture_test_root(&container).unwrap();
            // An ancestor that can no longer be searched fails the
            // container's own open, reported with its errno.
            mode(&ancestor, 0o000);
            let error = inputs.revalidate().unwrap_err();
            assert_eq!(custody_refusal_code(&error), CUSTODY_CONTAINER_ERRNO);
            assert_eq!(container_errno(&error), Some(libc::EACCES));
            mode(&ancestor, 0o700);
            inputs.revalidate().unwrap();
            drop(inputs);
            // An unreadable container carries the errno sub-code.
            mode(&container, 0o000);
            let error = CapturedAppGroupInputs::capture_test_root(&container)
                .err()
                .unwrap();
            assert_eq!(custody_refusal_code(&error), CUSTODY_CONTAINER_ERRNO);
            assert_eq!(container_errno(&error), Some(libc::EACCES));
            mode(&container, 0o700);
        }
        CapturedAppGroupInputs::capture_test_root(&container)
            .unwrap()
            .revalidate()
            .unwrap();
        std::fs::rename(&container, tree.root()).unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn app_group_container_anchor_requires_the_exact_held_path() {
        let base = private_test_base("getpath");
        let container = base.join("container");
        std::fs::create_dir(&container).unwrap();
        std::fs::set_permissions(&container, std::fs::Permissions::from_mode(0o700)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let held = open_container_anchor(&container).unwrap();
        assert_eq!(
            held_path(&held).unwrap(),
            container.as_os_str().as_encoded_bytes()
        );
        assert!(require_held_path(&held, &container).is_ok());
        assert_eq!(
            require_held_path(&held, &base),
            Err(ContainerAnchorFailure::Mismatch)
        );
        drop(held);
        // An intermediate symlink is followed by open(2) (O_NOFOLLOW covers
        // the final component only) and then refused by F_GETPATH.
        symlink(&base, base.with_extension("link")).unwrap();
        let linked = base.with_extension("link").join("container");
        assert_eq!(
            open_container_anchor(&linked).err(),
            Some(ContainerAnchorFailure::Mismatch)
        );
        std::fs::remove_file(base.with_extension("link")).unwrap();
        // On a case-insensitive volume another spelling opens the same
        // directory; only the exact on-disk spelling is the anchor.
        let upper = base.join("CONTAINER");
        if std::fs::symlink_metadata(&upper).is_ok() {
            assert_eq!(
                open_container_anchor(&upper).err(),
                Some(ContainerAnchorFailure::Mismatch)
            );
            let error = HeldContainer::open(&upper, uid).err().unwrap();
            assert_eq!(
                custody_refusal_code(&error),
                CUSTODY_CONTAINER_PATH_MISMATCH
            );
        }
        // The final component is never followed; an absent one is unresolved.
        symlink("container", base.join("alias")).unwrap();
        assert!(matches!(
            open_container_anchor(&base.join("alias")).err(),
            Some(ContainerAnchorFailure::Open(libc::ELOOP | libc::ENOTDIR))
        ));
        let error = HeldContainer::open(&base.join("absent"), uid)
            .err()
            .unwrap();
        assert_eq!(custody_refusal_code(&error), CONTAINER_UNRESOLVED);
        assert_eq!(
            custody_refusal_code(&anchor_refused(ContainerAnchorFailure::GetPath(
                libc::EBADF
            ))),
            CUSTODY_CONTAINER_PATH_MISMATCH
        );
        // `/` is never a container, even though it anchors exactly.
        assert!(open_container_anchor(Path::new("/")).is_ok());
        assert_eq!(
            custody_refusal_code(&HeldContainer::open(Path::new("/"), uid).err().unwrap()),
            "provider_app_group_custody_refused"
        );
        HeldContainer::open(&container, uid)
            .unwrap()
            .revalidate()
            .unwrap();
        std::fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn actual_private_file_generation_denies_links_fifo_and_replacement() {
        let base = std::env::temp_dir().join(format!(
            "aegis-appgroup-fd-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        let dir = File::open(&base).unwrap();
        let uid = unsafe { libc::geteuid() };
        let path = base.join("record");
        std::fs::write(&path, b"never-issued private fixture").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let held = HeldPrivateFile::open(&dir, "record", uid).unwrap();
        std::fs::hard_link(&path, base.join("link")).unwrap();
        assert!(held.revalidate().is_err());
        assert!(HeldPrivateFile::open(&dir, "record", uid).is_err());
        std::fs::remove_file(base.join("link")).unwrap();
        std::fs::rename(&path, base.join("old")).unwrap();
        std::fs::write(&path, b"replacement").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(held.revalidate().is_err());
        std::fs::remove_file(&path).unwrap();
        symlink(base.join("old"), &path).unwrap();
        assert!(HeldPrivateFile::open(&dir, "record", uid).is_err());
        std::fs::remove_file(&path).unwrap();
        let p = CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(p.as_ptr(), 0o600) }, 0);
        assert!(HeldPrivateFile::open(&dir, "record", uid).is_err());
        drop(held);
        drop(dir);
        std::fs::remove_dir_all(base).unwrap();
    }
}
