//! B-06 v45: `aegis-ne-host --enroll ABSOLUTE.aegis-invite [--remove-source]
//! [--replace-identity]`, the one-step join of a friend's Mac.
//!
//! The verb replaces the hand enrollment of 6 November (`aegis-client device
//! prepare`, `bundle-inspect` for the pin, `redeem`, then `aegis-ne-host
//! --import`) with one bounded run of the signed host:
//! 1. the package (`invite_package::read_package`) is admitted;
//! 2. the provider is asked (`precheck`): no live session, and no currently
//!    valid identity unless the user chose to replace it;
//! 3. `stage` writes the package's public bundle into a fresh private
//!    staging directory below `~/Library/Application Support/dev.aegis.macos/
//!    enroll/` (one per package: `InvitePackage::staging_name`), prepares
//!    the device key and CSR there, pins the profile and redeems the
//!    invitation with the enrollment authority (`enroll_journal`,
//!    `renewal_exchange::EnrollmentAuthority::redeem_attempt`), in process;
//! 4. `bin/host.rs` then runs the existing import of that staging tree with
//!    its administrator prompt and its exact manifest check, and removes the
//!    staging tree only on an exact commit (`host_import`, `--remove-source`
//!    semantics);
//! 5. with `--remove-source`, the package file is removed only after a
//!    commit and only while it is the very file that was read.
//!
//! A failed redeem keeps the staging tree: the next run with the same
//! package resumes the journaled request (its receipt is asked for first,
//! as the library's `perform` does), and an issued identity whose import was
//! not approved goes straight to the import. Every result is one stable
//! stdout line (`enroll_result=...`) and at most one stderr code; progress
//! lines (`enroll_progress=...`) and the codes never name a path, an
//! address or a byte of the token.
use crate::{
    enroll_journal::{self, EnrollJournal, Stand},
    host_import::ImportOutcome,
    host_lifecycle::{
        EXIT_ENROLL_IDENTITY_PRESENT, EXIT_ENROLL_LOCAL_FAILED, EXIT_ENROLL_PACKAGE_REFUSED,
        EXIT_ENROLL_RECOVERY_REQUIRED, EXIT_ENROLL_REJECTED, EXIT_ENROLL_SESSION_LIVE,
        EXIT_ENROLL_UNREACHABLE,
    },
    identity_renewal::FailureClass,
    invite_package::InvitePackage,
    menu_model::field,
    renewal_exchange::{clock_at_least, AttemptError, EnrollmentAuthority, ATTEMPTS},
};
use aegis_client::public_profile_file::MEMBERS;
use aegis_core::secure_channel::{
    enrollment::protocol::ProofPurpose,
    enrollment_wire::{ExchangeResponse, FailureCode},
    registry,
};
use std::{
    io,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

/// The staging root below `$HOME` (beside the import journal).
pub const ENROLL_DIR: &str = "Library/Application Support/dev.aegis.macos/enroll";

/// The stderr prefix of a progress line; the menu shows the step.
pub const PROGRESS: &str = "enroll_progress=";

/// The steps a progress line names, in order.
pub const STEPS: [&str; 6] = [
    "checking",
    "preparing",
    "contacting",
    "approving",
    "importing",
    "finishing",
];

/// The most one whole redeem (every attempt, waits included) may take.
pub const REDEEM_BUDGET: Duration = Duration::from_secs(60);
/// One attempt: connect, carrier, inner TLS, challenge to response.
const ATTEMPT_BUDGET: Duration = Duration::from_secs(15);

/// The prefix of this module's temporary files (never a final leaf).
const TEMP_PREFIX: &str = ".tmp-enroll-";

/// The stdout line when no administrator approved the import: the staged
/// identity is kept for the next run.
pub const APPROVAL_REFUSED_LINE: &str =
    "enroll_result=failed stage=approval redeem=done import=not_sent staging=kept invite=kept";
/// The stdout line when the import's commit state is unknown.
pub const IMPORT_UNKNOWN_LINE: &str =
    "enroll_result=unknown stage=import redeem=done import=unknown staging=kept invite=kept";

/// How a join ended before the import.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The package was refused (`invite_package` code). Nothing changed.
    Package(&'static str),
    /// A currently valid identity exists and the user did not choose to
    /// replace it. Nothing changed.
    IdentityPresent,
    /// A tunnel session is live. Nothing changed.
    SessionLive,
    /// The provider did not answer the precheck (its exit code: 69 or 75)
    /// and its code. Nothing changed.
    Provider(i32, &'static str),
    /// The authority rejected the invitation: expired, already used,
    /// revoked or not for this device. The staging tree is kept.
    Rejected,
    /// The authority asks for operator recovery. The staging tree is kept.
    RecoveryRequired,
    /// The authority was not reached, or answered only Busy/Unavailable
    /// (`enroll_authority_*`). The staging tree is kept; a rerun resumes.
    Unreachable(&'static str),
    /// A local staging, Store or journal check (`enroll_journal` code).
    Local(&'static str),
}

impl Failure {
    pub fn exit(self) -> i32 {
        match self {
            Self::Package(_) => EXIT_ENROLL_PACKAGE_REFUSED,
            Self::IdentityPresent => EXIT_ENROLL_IDENTITY_PRESENT,
            Self::SessionLive => EXIT_ENROLL_SESSION_LIVE,
            Self::Provider(exit, _) => exit,
            Self::Rejected => EXIT_ENROLL_REJECTED,
            Self::RecoveryRequired => EXIT_ENROLL_RECOVERY_REQUIRED,
            Self::Unreachable(_) => EXIT_ENROLL_UNREACHABLE,
            Self::Local(_) => EXIT_ENROLL_LOCAL_FAILED,
        }
    }

    /// The stderr code.
    pub fn code(self) -> &'static str {
        match self {
            Self::Package(code) | Self::Provider(_, code) | Self::Local(code) => code,
            Self::IdentityPresent => "enroll_identity_present",
            Self::SessionLive => "enroll_session_live",
            Self::Rejected => "enroll_invitation_rejected",
            Self::RecoveryRequired => "enroll_recovery_required",
            Self::Unreachable(code) => code,
        }
    }

    /// The one stdout line.
    pub fn line(self) -> String {
        let (result, stage, redeem, staging) = match self {
            Self::Package(_) => ("refused", "package", "not_run", "none"),
            Self::IdentityPresent | Self::SessionLive | Self::Provider(..) => {
                ("refused", "precheck", "not_run", "none")
            }
            Self::Rejected => ("failed", "redeem", "rejected", "kept"),
            Self::RecoveryRequired => ("failed", "redeem", "recovery_required", "kept"),
            Self::Unreachable(_) => ("failed", "redeem", "unreachable", "kept"),
            Self::Local(_) => ("failed", "stage", "not_done", "kept"),
        };
        format!(
            "enroll_result={result} stage={stage} redeem={redeem} import=not_sent staging={staging} invite=kept"
        )
    }
}

/// How the identity came to be issued in the staging Store.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Redeemed {
    /// Issued for a request of this run.
    Issued,
    /// A journaled request's (or saved response's) issuance, recovered.
    Resumed,
    /// Issued by an earlier run whose import did not finish.
    Earlier,
}

impl Redeemed {
    pub fn token(self) -> &'static str {
        match self {
            Self::Issued => "issued",
            Self::Resumed => "resumed",
            Self::Earlier => "earlier",
        }
    }
}

/// A staged, issued identity ready for the import.
#[derive(Debug)]
pub struct Staged {
    /// The staging directory (holds exactly `bundle/` and `identity/`).
    pub dir: PathBuf,
    pub redeemed: Redeemed,
    pub not_after: u64,
    /// The issued certificate's fingerprint (`admit_payload`).
    pub certificate_sha256: String,
}

/// The provider's session phases while a session lives.
pub const LIVE_PHASES: [&str; 3] = ["constructing", "ready", "sealed"];

/// What the provider said before anything is staged.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProviderView {
    /// `--ping`'s `identity_present`.
    pub identity_present: bool,
    /// `--status`'s session phase (`none` when idle) and last refusal.
    pub session_phase: String,
    pub session_refusal: Option<String>,
    /// `--cert-status`'s state and end, when it answered.
    pub cert_state: Option<String>,
    pub not_after: Option<u64>,
}

impl ProviderView {
    /// The held identity can no longer connect: expired (by the provider's
    /// record or our clock), superseded, or the last start refused it as
    /// expired.
    pub fn identity_dead(&self, now: u64) -> bool {
        matches!(self.cert_state.as_deref(), Some("expired" | "superseded"))
            || self.not_after.is_some_and(|end| end <= now)
            || self.session_refusal.as_deref() == Some("session_identity_expired")
    }
}

/// Refuse a join while a session is live, or over an identity that may
/// still work unless the user chose to replace it.
pub fn precheck(view: &ProviderView, replace: bool, now: u64) -> Result<(), Failure> {
    // `joined` is a session that ended: the provider keeps its record (and
    // its refusal) until it restarts. The provider's own `session_live`
    // gate at the import stays the authoritative check.
    if LIVE_PHASES.contains(&view.session_phase.as_str()) {
        return Err(Failure::SessionLive);
    }
    if view.identity_present && !replace && !view.identity_dead(now) {
        return Err(Failure::IdentityPresent);
    }
    Ok(())
}

/// `$HOME/ENROLL_DIR` from the canonical home directory, so the staging
/// path is canonical (the import admits only a canonical source).
pub fn staging_root(home: &Path) -> Result<PathBuf, Failure> {
    if !home.is_absolute() {
        return Err(Failure::Local(enroll_journal::LOCAL));
    }
    let home = std::fs::canonicalize(home).map_err(|_| Failure::Local(enroll_journal::LOCAL))?;
    Ok(home.join(ENROLL_DIR))
}

fn local(code: &'static str) -> Failure {
    Failure::Local(code)
}

/// A real directory of the caller with no group or other permission, never
/// through a link, created 0700 (with missing parents) when absent.
fn private_dir(path: &Path, exact: bool) -> Result<(), Failure> {
    match std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
    {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(_) => return Err(local(enroll_journal::WRITE)),
    }
    let meta = std::fs::symlink_metadata(path).map_err(|_| local(enroll_journal::LOCAL))?;
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let mode = meta.mode() & 0o7777;
    if !meta.is_dir()
        || meta.uid() != euid
        || mode & 0o077 != 0
        || (exact && mode != 0o700)
        || std::fs::canonicalize(path).ok().as_deref() != Some(path)
    {
        return Err(local(enroll_journal::CONFLICT));
    }
    Ok(())
}

fn names(dir: &Path) -> Result<Vec<String>, Failure> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|_| local(enroll_journal::LOCAL))? {
        let entry = entry.map_err(|_| local(enroll_journal::LOCAL))?;
        names.push(
            entry
                .file_name()
                .to_str()
                .ok_or(local(enroll_journal::CONFLICT))?
                .to_owned(),
        );
    }
    names.sort();
    Ok(names)
}

/// Exclude the staging tree (it holds the private key) from Time Machine,
/// as the provider's committed tree is.
pub(crate) fn exclude_from_backup(dir: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(dir.as_os_str().as_bytes()) else {
        return;
    };
    let value = crate::identity_import::BACKUP_EXCLUDE_VALUE;
    // SAFETY: NUL-terminated path and attribute name; `value` outlives the
    // call. A failure only leaves the tree in backups.
    unsafe {
        libc::setxattr(
            path.as_ptr(),
            crate::identity_import::BACKUP_EXCLUDE_XATTR.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
            libc::XATTR_NOFOLLOW,
        );
    }
}

/// The package's public bundle in `bundle/`: written once (0600), or, on a
/// resume, exactly the package's bytes.
fn write_bundle(bundle: &Path, package: &InvitePackage) -> Result<(), Failure> {
    private_dir(bundle, false)?;
    // An interrupted write of ours leaves only a temporary file.
    for name in names(bundle)? {
        if name.starts_with(TEMP_PREFIX) {
            let path = bundle.join(&name);
            if std::fs::symlink_metadata(&path).is_ok_and(|meta| meta.is_file()) {
                std::fs::remove_file(&path).map_err(|_| local(enroll_journal::WRITE))?;
            }
        }
    }
    if names(bundle)?
        .iter()
        .any(|name| !MEMBERS.contains(&name.as_str()))
    {
        return Err(local(enroll_journal::CONFLICT));
    }
    for (name, bytes) in MEMBERS.iter().zip(package.public()) {
        let path = bundle.join(name);
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                if !meta.is_file() || meta.nlink() != 1 {
                    return Err(local(enroll_journal::CONFLICT));
                }
                let existing = std::fs::read(&path).map_err(|_| local(enroll_journal::LOCAL))?;
                if existing != *bytes {
                    return Err(local(enroll_journal::CONFLICT));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // Whole or absent: a private temporary file, synced, then
                // renamed exclusively into place.
                use std::io::Write;
                let temp = bundle.join(format!("{TEMP_PREFIX}{}-{name}", std::process::id()));
                let written = (|| {
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                        .open(&temp)?;
                    file.write_all(bytes)?;
                    file.sync_all()?;
                    crate::renewal_journal::rename_exclusive(&temp, &path)
                })();
                if written.is_err() {
                    let _ = std::fs::remove_file(&temp);
                    return Err(local(enroll_journal::WRITE));
                }
            }
            Err(_) => return Err(local(enroll_journal::LOCAL)),
        }
    }
    std::fs::File::open(bundle)
        .and_then(|dir| dir.sync_all())
        .map_err(|_| local(enroll_journal::WRITE))
}

/// The private staging directory of `package` below `root` with its
/// `bundle/` written and its `identity/` Store open.
fn open_staging(package: &InvitePackage, root: &Path) -> Result<(PathBuf, EnrollJournal), Failure> {
    private_dir(root, false)?;
    let dir = root.join(package.staging_name());
    private_dir(&dir, true)?;
    exclude_from_backup(&dir);
    if names(&dir)?
        .iter()
        .any(|name| name != "bundle" && name != "identity")
    {
        return Err(local(enroll_journal::CONFLICT));
    }
    write_bundle(&dir.join("bundle"), package)?;
    let journal = EnrollJournal::open(&dir.join("identity")).map_err(local)?;
    Ok((dir, journal))
}

fn unreachable_code(class: FailureClass) -> &'static str {
    match class {
        FailureClass::ConnectTimeout | FailureClass::InterfaceUnresolved => {
            "enroll_authority_unreachable"
        }
        FailureClass::Timeout => "enroll_authority_timeout",
        _ => "enroll_authority_unavailable",
    }
}

fn now() -> Result<u64, Failure> {
    registry::unix_now().map_err(|_| local("enroll_clock_failed"))
}

/// One redeem, as the library's `perform`: at most `ATTEMPTS` connections;
/// a journaled request asks for its receipt first; a busy, unavailable or
/// broken attempt switches a journaled request to receipt recovery; a
/// rejected receipt query to a fresh authorization of the same request; a
/// rejected authorization or a required recovery ends it, the request kept.
/// The physical interface toward the authority (the bound socket helper's
/// own resolution, which refuses a tunnel or loopback route). Lib tests
/// reach their loopback authority through lo0, as the renewal tests do.
fn authority_interface(
    address: std::net::SocketAddr,
) -> Result<crate::relay_socket::RelayInterface, Failure> {
    #[cfg(test)]
    if address.ip().is_loopback() {
        return Ok(crate::relay_socket::RelayInterface::loopback_for_test());
    }
    crate::relay_socket::resolve_relay_interface(address)
        .map_err(|_| Failure::Unreachable("enroll_authority_unreachable"))
}

async fn redeem(
    journal: &EnrollJournal,
    authority: &EnrollmentAuthority,
    package: &InvitePackage,
) -> Result<Redeemed, Failure> {
    let interface = authority_interface(authority.address())?;
    let profile = package.profile_sha256();
    let mut material = journal
        .journaled(&profile, package.token())
        .map_err(local)?;
    let resumed = material.is_some();
    let mut purpose = if resumed {
        ProofPurpose::Receipt
    } else {
        ProofPurpose::Authorize
    };
    let mut last = "enroll_authority_unreachable";
    for attempt in 0..ATTEMPTS {
        let answered = tokio::time::timeout(
            ATTEMPT_BUDGET,
            authority.redeem_attempt(
                &interface,
                journal,
                &profile,
                package.token(),
                &mut material,
                purpose,
            ),
        )
        .await
        .unwrap_or(Err(AttemptError::Transport(FailureClass::Timeout)));
        match answered {
            Ok(ExchangeResponse::Issued { receipt }) => {
                let at = now()?;
                let accepted = match journal.accept(&profile, &receipt, at) {
                    Err(enroll_journal::NOT_YET_VALID) => {
                        let at = clock_at_least(receipt.not_before_unix_secs)
                            .await
                            .map_err(local)?;
                        journal.accept(&profile, &receipt, at)
                    }
                    other => other,
                };
                accepted.map_err(local)?;
                return Ok(if resumed {
                    Redeemed::Resumed
                } else {
                    Redeemed::Issued
                });
            }
            Ok(ExchangeResponse::Failed {
                code: FailureCode::Rejected,
            }) if purpose == ProofPurpose::Receipt => purpose = ProofPurpose::Authorize,
            Ok(ExchangeResponse::Failed {
                code: FailureCode::Rejected,
            }) => return Err(Failure::Rejected),
            Ok(ExchangeResponse::Failed {
                code: FailureCode::RecoveryRequired,
            }) => return Err(Failure::RecoveryRequired),
            Ok(ExchangeResponse::Failed {
                code: FailureCode::Busy | FailureCode::Unavailable,
            }) => {
                last = "enroll_authority_busy";
                if material.is_some() {
                    purpose = ProofPurpose::Receipt;
                }
            }
            Err(AttemptError::Transport(class)) => {
                last = unreachable_code(class);
                if material.is_some() {
                    purpose = ProofPurpose::Receipt;
                }
            }
            Err(AttemptError::Local(code)) => return Err(Failure::Local(code)),
        }
        if attempt + 1 < ATTEMPTS {
            tokio::time::sleep(Duration::from_millis(200 * u64::from(attempt + 1))).await;
        }
    }
    Err(Failure::Unreachable(last))
}

/// Whether a staging directory may be thrown away: a real directory of
/// ours whose identity holds no issued certificate and no saved response
/// (and, unless `with_request`, no journaled request: nothing of it was
/// ever sent), and whose Store lock no other join holds.
fn discardable(dir: &Path, with_request: bool) -> bool {
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    let ours = std::fs::symlink_metadata(dir)
        .is_ok_and(|meta| meta.is_dir() && !meta.file_type().is_symlink() && meta.uid() == euid);
    let identity = dir.join("identity");
    let absent = |leaf: &str| {
        matches!(
            std::fs::symlink_metadata(identity.join(leaf)),
            Err(error) if error.kind() == io::ErrorKind::NotFound
        )
    };
    let unissued = absent("device.pem")
        && absent(crate::renewal_journal::RESPONSE)
        && (with_request || absent(crate::renewal_journal::REQUEST));
    let unlocked = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(identity.join(".lock"))
    {
        Ok(lock) => lock.try_lock().is_ok(),
        Err(error) => error.kind() == io::ErrorKind::NotFound,
    };
    ours && unissued && unlocked
}

/// Remove a staging directory `discardable` admits; whether it is gone.
fn discard(dir: &Path, with_request: bool) -> bool {
    discardable(dir, with_request) && std::fs::remove_dir_all(dir).is_ok()
}

/// Stage `package` below `root` and redeem it: the issued identity, ready
/// for the import. `progress` is told each step (`STEPS`).
///
/// A staging tree that fails a local check before anything of it was sent
/// (a cut inside a write, a stray entry) is discarded and built once more.
/// A rejected invitation leaves nothing behind: its request can never be
/// issued, so the uncertified key and the dead token go.
pub fn stage(
    package: &InvitePackage,
    root: &Path,
    progress: &mut dyn FnMut(&'static str),
) -> Result<Staged, Failure> {
    progress("preparing");
    let dir = root.join(package.staging_name());
    match stage_once(package, root, progress) {
        Err(Failure::Local(code)) if code != enroll_journal::BUSY && discard(&dir, false) => {
            stage_once(package, root, progress)
        }
        Err(Failure::Rejected) => {
            discard(&dir, true);
            Err(Failure::Rejected)
        }
        other => other,
    }
}

fn stage_once(
    package: &InvitePackage,
    root: &Path,
    progress: &mut dyn FnMut(&'static str),
) -> Result<Staged, Failure> {
    let (dir, journal) = open_staging(package, root)?;
    let profile = package.profile_sha256();
    journal
        .prepare(package.device_id(), &package.public()[3])
        .map_err(local)?;
    journal.pin(&profile).map_err(local)?;
    let redeemed = match journal.stand(&profile).map_err(local)? {
        Stand::Responded => {
            journal
                .resume_response(&profile, now()?)
                .map_err(local)?
                .ok_or(local(enroll_journal::LOCAL))?;
            Redeemed::Resumed
        }
        Stand::Completed => Redeemed::Earlier,
        Stand::Prepared | Stand::Pending => {
            progress("contacting");
            let public = package.public().clone();
            let authority = EnrollmentAuthority::from_held(
                public,
                None,
                &dir.join("bundle"),
                &dir.join("identity"),
            )
            .map_err(|_| local("enroll_profile_refused"))?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(|_| local("enroll_runtime_failed"))?;
            runtime.block_on(async {
                tokio::time::timeout(REDEEM_BUDGET, redeem(&journal, &authority, package))
                    .await
                    .unwrap_or(Err(Failure::Unreachable("enroll_authority_timeout")))
            })?
        }
    };
    let completion = journal.completed(&profile, now()?).map_err(local)?;
    drop(journal);
    Ok(Staged {
        dir,
        redeemed,
        not_after: completion.not_after_unix_secs,
        certificate_sha256: completion.certificate_sha256,
    })
}

/// Every member an enroll import sends: the bundle and the issued identity,
/// never an optional sidecar.
pub const STAGED_MEMBERS: [&str; 11] = [
    "bundle/bundle.json",
    "bundle/outer-ca.pem",
    "bundle/inner-ca.pem",
    "bundle/device-ca.pem",
    "identity/identity.json",
    "identity/device.key",
    "identity/device.csr",
    "identity/device.pem",
    "identity/device-ca.pem",
    "identity/bundle-profile.sha256",
    "identity/online-completed.json",
];

/// The payload the import read (`SourceTree::open`, the bytes it sends) is
/// this package's issued identity and nothing else: exactly
/// `STAGED_MEMBERS`, the package's bundle, CA and pin, a record and a
/// completed receipt of the package's device and of the certificate
/// `stage` issued. Anything else is `enroll_staging_changed`, nothing sent.
pub fn admit_payload(
    package: &InvitePackage,
    staged: &Staged,
    payload: &crate::identity_import::ImportPayload,
) -> Result<(), &'static str> {
    const CHANGED: &str = "enroll_staging_changed";
    let files: std::collections::BTreeMap<&str, &[u8]> = payload
        .files()
        .map(|(member, bytes)| (member.name(), bytes))
        .collect();
    let mut expected = STAGED_MEMBERS.to_vec();
    expected.sort_unstable();
    if files.keys().copied().collect::<Vec<_>>() != expected {
        return Err(CHANGED);
    }
    for (name, bytes) in MEMBERS.iter().zip(package.public()) {
        if files[format!("bundle/{name}").as_str()] != bytes.as_slice() {
            return Err(CHANGED);
        }
    }
    if files["identity/device-ca.pem"] != package.public()[3].as_slice()
        || files["identity/bundle-profile.sha256"] != package.profile_sha256().as_bytes()
    {
        return Err(CHANGED);
    }
    let record = crate::renewal_journal::Record::parse(files["identity/identity.json"])
        .map_err(|_| CHANGED)?;
    let completed =
        crate::renewal_journal::SavedResponse::parse(files["identity/online-completed.json"])
            .map_err(|_| CHANGED)?;
    if record.device_id != package.device_id()
        || record.phase != "ready"
        || record.certificate_sha256.as_deref() != Some(staged.certificate_sha256.as_str())
        || completed.receipt.device_id != package.device_id()
        || completed.receipt.certificate_sha256 != staged.certificate_sha256
    {
        return Err(CHANGED);
    }
    Ok(())
}

/// After a commit: remove every other staging directory below `root` that
/// never received a certificate (an abandoned or rejected join: an
/// uncertified key and an unspent or dead token), unless a join holds it.
/// The number removed.
pub fn sweep_unissued(root: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let name = entry.file_name();
        let staging = name
            .to_str()
            .is_some_and(|name| name.len() == 32 && name.bytes().all(|b| b.is_ascii_hexdigit()));
        if staging && discard(&entry.path(), true) {
            removed += 1;
        }
    }
    removed
}

/// The stdout line after the import of a staged identity: `import` and
/// `staging` from the import's own line, `invite` what became of the
/// package file.
pub fn import_line(redeemed: Redeemed, import: &ImportOutcome, invite: &str) -> String {
    let result = field(&import.stdout, "import_result").unwrap_or("unknown");
    let staging = match field(&import.stdout, "source") {
        Some("removed") => "removed",
        _ => "kept",
    };
    let (outcome, stage) = match result {
        "committed" => ("joined", "done"),
        "unknown" => ("unknown", "import"),
        _ => ("failed", "import"),
    };
    format!(
        "enroll_result={outcome} stage={stage} redeem={} import={result} staging={staging} invite={invite}",
        redeemed.token()
    )
}

/// Whether the import committed the identity (its exit: 0, or 73/74 with
/// something left behind).
pub fn import_committed(import: &ImportOutcome) -> bool {
    field(&import.stdout, "import_result") == Some("committed")
}

#[cfg(test)]
#[path = "host_enroll_tests.rs"]
mod tests;
