//! B-06 S23: the provider's same-key renewal journal over the protected Store.
//!
//! This is the Renew subset of aegis-client's binary-private online journal
//! (`device_identity_online.rs`: resume, status, begin, sign, accept,
//! finish), with the same files, bytes, checks and write order, held under
//! one `ProtectedIdentityStore` lock. It exists here only because that
//! implementation, its writable Store and its `Store::save` are private to
//! the aegis-client binary; the shared change that moves them into the
//! library (one implementation for both callers) is recorded for merge.
//!
//! Write order of a renewal, each write atomic (private temp file in the
//! identity directory, fsync, rename or exclusive rename, directory fsync):
//! 1. `online-request.json` (no clobber, v32: or a parked request renamed
//!    back exclusively), before the request's first byte;
//! 2. `online-response.json` (no clobber), only after the issued receipt
//!    verified against the held key, the pinned device CA, the profile pin
//!    and the predecessor it must extend (v32: a parked request beside it is
//!    removed first);
//! 3. `device.pem` replaced, only while it is still that predecessor;
//! 4. `identity.json` rewritten, then the installed facts verified again;
//! 5. `online-completed.json` replaced; 6. the request, then the response
//!    removed. A cut anywhere leaves either the old identity with a journal
//!    or a saved response that `resume_response` finishes exactly once.
//!
//! An invitation (Redeem) request is never parsed here: its token must not
//! reach unzeroized memory, and a ready provider identity never has one.
//!
//! v32 (S23c): every local refusal names its check (`CHECKS`), and a
//! request the authority only ever rejected (Rejected or RecoveryRequired,
//! never an issued answer) can be parked: [`RenewalJournal::park`] renames
//! our own `online-request.json` to `online-request.parked.json`
//! (`PARKED`) under the held lock, so it no longer blocks the capture of
//! the installed certificate (the capture and the library refuse only the
//! three journal leaves). The parked request keeps its request id: a later
//! attempt resumes it, signs its proof from `PARKED` and renames it back
//! ([`RenewalJournal::unpark`], exclusive, directory synced) before the
//! request's first byte, so "durable before the first byte" holds for
//! every request. A parked request whose predecessor is no longer the
//! installed certificate is stale: ignored by the status and the capture,
//! and only a stale one is ever renamed over. `accept` removes a parked
//! request beside the journaled one once that request's issued receipt
//! verified and before `online-response.json`, so before any identity
//! write: the verified issuance for that predecessor means the authority
//! no longer lists it, so a parked request of it (or of an older
//! certificate) can never be issued (v32 review: one that cannot be read
//! is left in place, never a refusal of that issuance). An issued receipt
//! this module refuses is never parked.
use aegis_client::{
    protected_identity_file::validate_file, protected_identity_store::ProtectedIdentityStore,
    protected_online_expectation::ProtectedOnlineExpectation,
};
use aegis_core::secure_channel::{
    enrollment::{
        self,
        protocol::{self, ChallengeMessage, Operation, ProofPurpose, RequestBinding},
        ValidatedDeviceCertificate,
    },
    enrollment_wire::EnrollmentReceipt,
    registry,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    ffi::CString,
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::Zeroizing;

pub(crate) const REQUEST: &str = "online-request.json";
/// v32: a parked Renew request (the bytes of `online-request.json`): every
/// answer seen for it was Rejected or RecoveryRequired. Never a journal leaf
/// of the capture, the library or an import.
pub(crate) const PARKED: &str = "online-request.parked.json";
pub(crate) const RESPONSE: &str = "online-response.json";
pub(crate) const COMPLETED: &str = "online-completed.json";
const MIGRATION: &str = "online-profile-migration.json";
const PROFILE: &str = "bundle-profile.sha256";
const MAX_ONLINE: usize = 256 * 1024;

/// Store or file integrity: a record, profile pin, pinned CA, key, CSR or
/// journal encoding check failed, or the Store's generation changed (v32:
/// receipt checks and journal I/O have their own codes).
pub(crate) const LOCAL_REFUSED: &str = "renewal_local_refused";
/// v32: a journal write, rename or removal, or its directory sync, failed.
pub(crate) const JOURNAL_WRITE: &str = "renewal_journal_write";
/// v32: a parked request that cannot be read, parsed or validated, or that
/// names the installed certificate beside a journaled request: it is never
/// renamed over, and no fresh request is written beside it (an unreadable
/// one is never removed either; v32 review: nor a reason to refuse a
/// verified issuance of the journaled request).
pub(crate) const PARKED_REFUSED: &str = "renewal_parked_refused";
/// v32: the issued receipt is malformed (`EnrollmentReceipt::validate`).
pub(crate) const RECEIPT_MALFORMED: &str = "renewal_receipt_malformed";
/// v32: the receipt names another profile pin, operation, request binding
/// or predecessor.
pub(crate) const RECEIPT_BINDING: &str = "renewal_receipt_binding";
/// v32: the receipt names another device id or CSR.
pub(crate) const RECEIPT_IDENTITY: &str = "renewal_receipt_identity";
/// v32: the successor does not chain to the pinned device CA with the held
/// key, the device id, the EKU and a lifetime the CA covers.
pub(crate) const SUCCESSOR_CERTIFICATE: &str = "renewal_successor_certificate";
/// v32: the receipt's fingerprint or window is not the signed certificate's.
pub(crate) const RECEIPT_METADATA: &str = "renewal_receipt_metadata";
/// v32: the successor has already expired by our clock (an authority clock
/// behind ours, or a stale replay): transient, never definitive.
pub(crate) const SUCCESSOR_EXPIRED: &str = "renewal_successor_expired";
/// v32: the successor was signed before the predecessor's due instant: no
/// renewal of it (a rollback or replay of an older certificate).
pub(crate) const SUCCESSOR_BEFORE_DUE: &str = "renewal_successor_before_due";
/// v32: the successor was signed at or after the predecessor's expiry.
pub(crate) const SUCCESSOR_AFTER_EXPIRY: &str = "renewal_successor_after_expiry";
/// v32: the successor ends no later than the predecessor (the shared
/// library's "must extend" rule; B-06 incident 27 October 2026).
pub(crate) const SUCCESSOR_NOT_EXTENDING: &str = "renewal_successor_not_extending";
/// The Store lock is held by another owner.
pub(crate) const BUSY: &str = "identity_renewal_busy";
/// A new Renew request before two thirds of the lifetime (library rule).
pub(crate) const NOT_DUE: &str = "renewal_not_due";
/// The predecessor has expired: only receipt recovery remains.
pub(crate) const PREDECESSOR_EXPIRED: &str = "renewal_predecessor_expired";
/// A journal names another request, response or certificate.
pub(crate) const CONFLICT: &str = "renewal_journal_conflict";
/// An issued successor whose signed `not_before` is still ahead of our clock
/// (the authority's clock leads ours); nothing was saved.
pub(crate) const NOT_YET_VALID: &str = "renewal_successor_not_yet_valid";
/// Test-only: the injected cut point was reached; nothing after it ran.
#[cfg(test)]
pub(crate) const CRASHED: &str = "renewal_test_crash";

/// v32: the receipt checks that judge only the receipt and the unchanged
/// Store, never our clock or I/O: an issued receipt one of them refuses is
/// refused identically at every receipt recovery (the authority replays it
/// byte for byte).
pub(crate) const DEFINITIVE: [&str; 8] = [
    RECEIPT_MALFORMED,
    RECEIPT_BINDING,
    RECEIPT_IDENTITY,
    SUCCESSOR_CERTIFICATE,
    RECEIPT_METADATA,
    SUCCESSOR_BEFORE_DUE,
    SUCCESSOR_AFTER_EXPIRY,
    SUCCESSOR_NOT_EXTENDING,
];

/// v32: whether `code` is a definitive receipt check (`DEFINITIVE`).
pub(crate) fn definitive(code: &str) -> bool {
    DEFINITIVE.contains(&code)
}

/// v32: every stable code this module returns (each must be listed in
/// `provider_xpc::RENEWAL_CHECKS`, which the host decodes against).
#[cfg(test)]
pub(crate) const CHECKS: [&str; 17] = [
    LOCAL_REFUSED,
    BUSY,
    NOT_DUE,
    PREDECESSOR_EXPIRED,
    CONFLICT,
    NOT_YET_VALID,
    JOURNAL_WRITE,
    PARKED_REFUSED,
    RECEIPT_MALFORMED,
    RECEIPT_BINDING,
    RECEIPT_IDENTITY,
    SUCCESSOR_CERTIFICATE,
    RECEIPT_METADATA,
    SUCCESSOR_EXPIRED,
    SUCCESSOR_BEFORE_DUE,
    SUCCESSOR_AFTER_EXPIRY,
    SUCCESSOR_NOT_EXTENDING,
];

pub(crate) type JResult<T> = Result<T, &'static str>;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn sha(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn local<T, E>(result: Result<T, E>) -> JResult<T> {
    result.map_err(|_| LOCAL_REFUSED)
}

/// v32: journal I/O (a write, rename, removal or directory sync).
fn write<T, E>(result: Result<T, E>) -> JResult<T> {
    result.map_err(|_| JOURNAL_WRITE)
}

/// An exclusive rename (`renamex_np` with `RENAME_EXCL`): never over an
/// existing entry.
pub(crate) fn rename_exclusive(from: &Path, to: &Path) -> io::Result<()> {
    let from = CString::new(from.as_os_str().as_bytes())?;
    let to = CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: both are NUL-terminated paths valid for the call.
    if unsafe { libc::renamex_np(from.as_ptr(), to.as_ptr(), libc::RENAME_EXCL) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One value in serde_json's compact form, as the binary's derive writes it.
macro_rules! json {
    ($value:expr) => {
        local(serde_json::to_string($value))
    };
}

fn exact<'a>(value: &'a Value, keys: &[&str]) -> JResult<&'a serde_json::Map<String, Value>> {
    let object = value.as_object().ok_or(LOCAL_REFUSED)?;
    if object.len() != keys.len() || !keys.iter().all(|key| object.contains_key(*key)) {
        return Err(LOCAL_REFUSED);
    }
    Ok(object)
}

fn optional_pem(value: &Value) -> JResult<Option<String>> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => Ok(Some(text.clone())),
        _ => Err(LOCAL_REFUSED),
    }
}

/// `identity.json`, the binary's `Record` field for field (v45: shared with
/// the host's Redeem journal, `enroll_journal`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Record {
    pub(crate) device_id: String,
    pub(crate) phase: String,
    pub(crate) device_ca_sha256: String,
    pub(crate) certificate_sha256: Option<String>,
}

impl Record {
    pub(crate) fn parse(bytes: &[u8]) -> JResult<Self> {
        let value: Value = local(serde_json::from_slice(bytes))?;
        let object = exact(
            &value,
            &[
                "version",
                "device_id",
                "phase",
                "device_ca_sha256",
                "certificate_sha256",
            ],
        )?;
        let text = |key: &str| object[key].as_str().map(str::to_owned).ok_or(LOCAL_REFUSED);
        let record = Self {
            device_id: text("device_id")?,
            phase: text("phase")?,
            device_ca_sha256: text("device_ca_sha256")?,
            certificate_sha256: optional_pem(&object["certificate_sha256"])?,
        };
        local(registry::validate_device_id(&record.device_id))?;
        if object["version"].as_u64() != Some(1)
            || !matches!(record.phase.as_str(), "initializing" | "prepared" | "ready")
        {
            return Err(LOCAL_REFUSED);
        }
        Ok(record)
    }

    /// The binary's `serde_json::to_vec(&Record)` bytes, field order kept.
    pub(crate) fn encode(&self) -> JResult<Vec<u8>> {
        Ok(format!(
            "{{\"version\":1,\"device_id\":{},\"phase\":{},\"device_ca_sha256\":{},\"certificate_sha256\":{}}}",
            json!(&self.device_id)?,
            json!(&self.phase)?,
            json!(&self.device_ca_sha256)?,
            json!(&self.certificate_sha256)?,
        )
        .into_bytes())
    }
}

/// `online-request.json` of a Renew request (no invitation).
#[derive(Clone)]
struct Pending {
    binding: RequestBinding,
    predecessor_certificate_pem: Option<String>,
}

impl Pending {
    fn parse(bytes: &[u8]) -> JResult<Self> {
        // A Redeem request carries an invitation: never parse its token.
        if !bytes
            .windows(b"\"invitation\":null".len())
            .any(|window| window == b"\"invitation\":null")
            || bytes
                .windows(b"\"operation\":\"redeem\"".len())
                .any(|window| window == b"\"operation\":\"redeem\"")
        {
            return Err(LOCAL_REFUSED);
        }
        let value: Value = local(serde_json::from_slice(bytes))?;
        let object = exact(
            &value,
            &[
                "version",
                "binding",
                "predecessor_certificate_pem",
                "invitation",
            ],
        )?;
        if object["version"].as_u64() != Some(1) || !object["invitation"].is_null() {
            return Err(LOCAL_REFUSED);
        }
        Ok(Self {
            binding: local(serde_json::from_value(object["binding"].clone()))?,
            predecessor_certificate_pem: optional_pem(&object["predecessor_certificate_pem"])?,
        })
    }

    fn encode(&self) -> JResult<Vec<u8>> {
        Ok(format!(
            "{{\"version\":1,\"binding\":{},\"predecessor_certificate_pem\":{},\"invitation\":null}}",
            json!(&self.binding)?,
            json!(&self.predecessor_certificate_pem)?,
        )
        .into_bytes())
    }
}

/// `online-response.json` and `online-completed.json`.
#[derive(Clone)]
pub(crate) struct SavedResponse {
    pub(crate) receipt: EnrollmentReceipt,
    pub(crate) predecessor_certificate_pem: Option<String>,
}

impl SavedResponse {
    pub(crate) fn parse(bytes: &[u8]) -> JResult<Self> {
        let value: Value = local(serde_json::from_slice(bytes))?;
        let object = exact(
            &value,
            &["version", "receipt", "predecessor_certificate_pem"],
        )?;
        if object["version"].as_u64() != Some(1) {
            return Err(LOCAL_REFUSED);
        }
        Ok(Self {
            receipt: local(serde_json::from_value(object["receipt"].clone()))?,
            predecessor_certificate_pem: optional_pem(&object["predecessor_certificate_pem"])?,
        })
    }

    pub(crate) fn encode(&self) -> JResult<Vec<u8>> {
        Ok(format!(
            "{{\"version\":1,\"receipt\":{},\"predecessor_certificate_pem\":{}}}",
            json!(&self.receipt)?,
            json!(&self.predecessor_certificate_pem)?,
        )
        .into_bytes())
    }

    pub(crate) fn same_receipt(&self, receipt: &EnrollmentReceipt) -> bool {
        matches!(
            (serde_json::to_vec(&self.receipt), serde_json::to_vec(receipt)),
            (Ok(left), Ok(right)) if left == right
        )
    }
}

/// What a Renew request sends: its binding, CSR and predecessor.
#[derive(Clone)]
pub(crate) struct RequestMaterial {
    pub(crate) binding: RequestBinding,
    pub(crate) csr_pem: String,
    pub(crate) predecessor_certificate_pem: Option<String>,
}

/// A finished renewal: the installed successor's public facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub(crate) certificate_sha256: String,
    pub(crate) not_before_unix_secs: u64,
    pub(crate) not_after_unix_secs: u64,
    pub(crate) valid_now: bool,
}

/// The installed identity's window and journal, as `online_status` reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Status {
    pub(crate) not_before_unix_secs: u64,
    pub(crate) not_after_unix_secs: u64,
    /// A journaled Renew request (or saved response) is unfinished.
    pub(crate) pending: bool,
    /// The active request (journaled or parked) names the installed
    /// certificate as predecessor: receipt recovery remains possible even
    /// after it expired.
    pub(crate) recoverable: bool,
    /// v32: no request is journaled and a parked request names the
    /// installed certificate (it does not block the capture).
    pub(crate) parked: bool,
    /// v32: no request is journaled and `PARKED` cannot be read, parsed or
    /// validated: renewal is refused (`PARKED_REFUSED`), the capture is not.
    pub(crate) parked_refused: bool,
}

/// v32: where the active Renew request is kept.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Leaf {
    /// `online-request.json`: blocks the capture.
    Request,
    /// `online-request.parked.json` naming the installed certificate.
    Parked,
}

/// Test-only cut points: the step returns `CRASHED` right after the named
/// durable write, leaving the disk exactly as a power cut there would.
#[cfg(test)]
pub(crate) mod cut {
    use std::cell::Cell;
    thread_local! {
        static AT: Cell<Option<&'static str>> = const { Cell::new(None) };
    }
    pub(crate) fn set(point: Option<&'static str>) {
        AT.with(|at| at.set(point));
    }
    pub(crate) fn hit(point: &'static str) -> bool {
        AT.with(|at| at.get() == Some(point))
    }
}

macro_rules! cut_point {
    ($point:literal) => {
        #[cfg(test)]
        if cut::hit($point) {
            return Err(CRASHED);
        }
    };
}

/// The protected Store lock plus this module's atomic writer.
pub(crate) struct RenewalJournal {
    store: ProtectedIdentityStore,
    directory: PathBuf,
    profile_sha256: String,
}

fn busy(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::fs::TryLockError>()
            .is_some_and(|error| matches!(error, std::fs::TryLockError::WouldBlock))
            || cause
                .downcast_ref::<io::Error>()
                .is_some_and(|error| error.kind() == io::ErrorKind::WouldBlock)
    })
}

fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
}

/// A device certificate's facts against the pinned CA and the held key:
/// chain, device id, key, EKU and lifetime, judged at its own `not_before`.
pub(crate) fn facts_with(
    record: &Record,
    ca: &[u8],
    key: &[u8],
    certificate: &[u8],
) -> JResult<ValidatedDeviceCertificate> {
    let facts = local(enrollment::device_certificate_metadata(
        &record.device_id,
        certificate,
        ca,
    ))?;
    local(enrollment::validate_device_certificate(
        &record.device_id,
        certificate,
        ca,
        key,
        facts.not_before_unix_secs,
    ))?;
    Ok(facts)
}

impl RenewalJournal {
    /// Open the existing protected Store at `directory` (never creates it);
    /// `profile_sha256` is the held public profile digest.
    pub(crate) fn open(directory: &Path, profile_sha256: &str) -> JResult<Self> {
        local(protocol::digest(profile_sha256))?;
        let store = ProtectedIdentityStore::open_existing(directory).map_err(|error| {
            if busy(&error) {
                BUSY
            } else {
                LOCAL_REFUSED
            }
        })?;
        Ok(Self {
            store,
            directory: directory.to_owned(),
            profile_sha256: profile_sha256.to_owned(),
        })
    }

    /// The library's validator over this same held lock.
    pub(crate) fn expectation(
        &self,
        now: u64,
    ) -> JResult<aegis_client::online_expectation::OnlineExpectation> {
        let expected = local(ProtectedOnlineExpectation::from_held(
            &self.store,
            &self.profile_sha256,
        ))?;
        local(expected.expectation_at(now))
    }

    fn read(&self, name: &str) -> JResult<Zeroizing<Vec<u8>>> {
        local(self.store.read(name))
    }

    fn read_online(&self, name: &str) -> JResult<Option<Zeroizing<Vec<u8>>>> {
        match self.store.read_online(name) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if missing(&error) => Ok(None),
            Err(_) => Err(LOCAL_REFUSED),
        }
    }

    fn pending(&self) -> JResult<Option<Pending>> {
        self.read_online(REQUEST)?
            .map(|bytes| Pending::parse(&bytes))
            .transpose()
    }

    fn response(&self, name: &str) -> JResult<Option<SavedResponse>> {
        self.read_online(name)?
            .map(|bytes| SavedResponse::parse(&bytes))
            .transpose()
    }

    /// Whether any journal leaf (request, response or migration) exists.
    pub(crate) fn journal_present(&self) -> JResult<bool> {
        for name in [REQUEST, RESPONSE, MIGRATION] {
            if self.read_online(name)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// `Store::save`: a private temp file in the identity directory, synced,
    /// then renamed over (`replace`) or exclusively renamed into place, and
    /// the directory synced. An existing leaf must be a private file.
    fn save(&self, name: &str, bytes: &[u8], replace: bool) -> JResult<()> {
        if bytes.len() > MAX_ONLINE {
            return Err(LOCAL_REFUSED);
        }
        local(self.store.revalidate())?;
        let path = self.directory.join(name);
        if replace {
            local(validate_file(&local(std::fs::symlink_metadata(&path))?))?;
        }
        let staging = self.directory.join(format!(
            ".tmp-renew-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let written = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&staging)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            if replace {
                std::fs::rename(&staging, &path)
            } else {
                rename_exclusive(&staging, &path)
            }
        })();
        if written.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        write(written)?;
        self.sync_directory()?;
        local(self.store.revalidate())
    }

    fn sync_directory(&self) -> JResult<()> {
        write(File::open(&self.directory).and_then(|dir| dir.sync_all()))
    }

    fn remove(&self, name: &str) -> JResult<()> {
        self.read_online(name)?.ok_or(LOCAL_REFUSED)?;
        write(std::fs::remove_file(self.directory.join(name)))?;
        self.sync_directory()
    }

    /// v32: rename our own private leaf `from` to `to` in the identity
    /// directory (`replace`: over an existing `to`, else exclusively), then
    /// sync the directory; the held Store generation is checked around it.
    fn rename_leaf(&self, from: &str, to: &str, replace: bool) -> JResult<()> {
        local(self.store.revalidate())?;
        let (from, to) = (self.directory.join(from), self.directory.join(to));
        write(if replace {
            std::fs::rename(&from, &to)
        } else {
            rename_exclusive(&from, &to)
        })?;
        self.sync_directory()?;
        local(self.store.revalidate())
    }

    /// v32: the parked request, if any. Anything but a missing leaf or a
    /// well-formed Renew request is `PARKED_REFUSED`.
    fn parked_request(&self) -> JResult<Option<Pending>> {
        match self.store.read_online(PARKED) {
            Ok(bytes) => Pending::parse(&bytes).map(Some).map_err(|_| PARKED_REFUSED),
            Err(error) if missing(&error) => Ok(None),
            Err(_) => Err(PARKED_REFUSED),
        }
    }

    /// v32: the active Renew request: the journaled one, else a parked one
    /// whose predecessor is the record's certificate (validated as a
    /// journaled one would be; a stale one, of another certificate, is
    /// none). An unreadable or invalid parked request is `PARKED_REFUSED`.
    fn active(&self, record: &Record) -> JResult<Option<(Leaf, Pending)>> {
        if let Some(pending) = self.pending()? {
            return Ok(Some((Leaf::Request, pending)));
        }
        let Some(parked) = self.parked_request()? else {
            return Ok(None);
        };
        if parked.binding.predecessor_sha256.is_none()
            || parked.binding.predecessor_sha256 != record.certificate_sha256
        {
            return Ok(None);
        }
        self.validate_pending(record, &parked)
            .map_err(|_| PARKED_REFUSED)?;
        Ok(Some((Leaf::Parked, parked)))
    }

    /// v32: whether the active request is parked (after a step: a parked
    /// request whose unpark never ran keeps the capture open).
    pub(crate) fn is_parked(&self) -> bool {
        self.record()
            .and_then(|record| self.active(&record))
            .is_ok_and(|active| matches!(active, Some((Leaf::Parked, _))))
    }

    fn record(&self) -> JResult<Record> {
        Record::parse(&self.read("identity.json")?)
    }

    fn profile(&self) -> JResult<()> {
        if std::str::from_utf8(&self.read(PROFILE)?)
            .map(str::trim)
            .ok()
            != Some(self.profile_sha256.as_str())
            || self.read_online(MIGRATION)?.is_some()
        {
            return Err(LOCAL_REFUSED);
        }
        Ok(())
    }

    fn pinned_ca(&self, record: &Record) -> JResult<Vec<u8>> {
        let ca = self.read("device-ca.pem")?;
        if sha(&ca) != record.device_ca_sha256 {
            return Err(LOCAL_REFUSED);
        }
        Ok(ca.to_vec())
    }

    fn validate_prepared(&self, record: &Record) -> JResult<()> {
        self.pinned_ca(record)?;
        let key = self.read("device.key")?;
        let expected = local(enrollment::csr_for_key(
            &record.device_id,
            local(std::str::from_utf8(&key))?,
        ))?;
        if self.read("device.csr")?.as_slice() != expected.as_bytes() {
            return Err(LOCAL_REFUSED);
        }
        Ok(())
    }

    fn facts(&self, record: &Record, certificate: &[u8]) -> JResult<ValidatedDeviceCertificate> {
        let ca = self.pinned_ca(record)?;
        facts_with(record, &ca, &self.read("device.key")?, certificate)
    }

    fn validate_pending(&self, record: &Record, pending: &Pending) -> JResult<()> {
        local(pending.binding.validate())?;
        if pending.binding.profile_sha256 != self.profile_sha256
            || pending.binding.operation != Operation::Renew
            || record.phase != "ready"
        {
            return Err(LOCAL_REFUSED);
        }
        self.profile()?;
        self.validate_prepared(record)?;
        if sha(&self.read("device.csr")?) != pending.binding.csr_sha256 {
            return Err(LOCAL_REFUSED);
        }
        let predecessor = pending
            .predecessor_certificate_pem
            .as_deref()
            .ok_or(LOCAL_REFUSED)?;
        let predecessor = self.facts(record, predecessor.as_bytes())?;
        if Some(&predecessor.fingerprint) != pending.binding.predecessor_sha256.as_ref() {
            return Err(LOCAL_REFUSED);
        }
        if record.certificate_sha256.as_ref() != pending.binding.predecessor_sha256.as_ref() {
            // Only a saved response for this very request may have advanced
            // the record past the predecessor.
            let response = self.response(RESPONSE)?.ok_or(CONFLICT)?;
            if response.receipt.binding != pending.binding
                || record.certificate_sha256.as_ref() != Some(&response.receipt.certificate_sha256)
            {
                return Err(CONFLICT);
            }
        }
        Ok(())
    }

    fn validate_response(
        &self,
        record: &Record,
        response: &SavedResponse,
        now: u64,
        history: bool,
    ) -> JResult<()> {
        let receipt = &response.receipt;
        receipt.validate().map_err(|_| RECEIPT_MALFORMED)?;
        if receipt.binding.profile_sha256 != self.profile_sha256
            || receipt.binding.operation != Operation::Renew
        {
            return Err(RECEIPT_BINDING);
        }
        self.profile()?;
        self.validate_prepared(record)?;
        if receipt.device_id != record.device_id
            || receipt.binding.csr_sha256 != sha(&self.read("device.csr")?)
        {
            return Err(RECEIPT_IDENTITY);
        }
        // The pinned CA and the held key are read once, so a Store read
        // failure is never classed as the successor's own (definitive).
        let ca = self.pinned_ca(record)?;
        let key = self.read("device.key")?;
        let signed = facts_with(record, &ca, &key, receipt.certificate_pem.as_bytes())
            .map_err(|_| SUCCESSOR_CERTIFICATE)?;
        if signed.fingerprint != receipt.certificate_sha256
            || signed.not_before_unix_secs != receipt.not_before_unix_secs
            || signed.not_after_unix_secs != receipt.not_after_unix_secs
        {
            return Err(RECEIPT_METADATA);
        }
        if !history && now >= signed.not_after_unix_secs {
            return Err(SUCCESSOR_EXPIRED);
        }
        if !history && now < signed.not_before_unix_secs {
            return Err(NOT_YET_VALID);
        }
        let predecessor = facts_with(
            record,
            &ca,
            &key,
            response
                .predecessor_certificate_pem
                .as_deref()
                .ok_or(LOCAL_REFUSED)?
                .as_bytes(),
        )?;
        let due = crate::identity_renewal::renewal_due_at(
            predecessor.not_before_unix_secs,
            predecessor.not_after_unix_secs,
        );
        if receipt.binding.predecessor_sha256.as_ref() != Some(&predecessor.fingerprint) {
            return Err(RECEIPT_BINDING);
        }
        if signed.not_before_unix_secs < due {
            return Err(SUCCESSOR_BEFORE_DUE);
        }
        if signed.not_before_unix_secs >= predecessor.not_after_unix_secs {
            return Err(SUCCESSOR_AFTER_EXPIRY);
        }
        if signed.not_after_unix_secs <= predecessor.not_after_unix_secs {
            return Err(SUCCESSOR_NOT_EXTENDING);
        }
        Ok(())
    }

    fn finish_response(&self, response: &SavedResponse, now: u64) -> JResult<Completion> {
        let mut record = self.record()?;
        self.validate_response(&record, response, now, true)?;
        let receipt = &response.receipt;
        // Both journals are checked before either certificate or record moves.
        if let Some(pending) = self.pending()? {
            self.validate_pending(&record, &pending)?;
            if pending.binding != receipt.binding
                || pending.predecessor_certificate_pem != response.predecessor_certificate_pem
            {
                return Err(CONFLICT);
            }
        }
        let existing = self.read("device.pem")?;
        let current = self.facts(&record, &existing)?;
        if current.fingerprint != receipt.certificate_sha256 {
            if receipt.binding.predecessor_sha256.as_ref() != Some(&current.fingerprint)
                || record.certificate_sha256.as_ref() != Some(&current.fingerprint)
            {
                return Err(CONFLICT);
            }
            self.save("device.pem", receipt.certificate_pem.as_bytes(), true)?;
            cut_point!("certificate_replaced");
        } else if existing.as_slice() != receipt.certificate_pem.as_bytes() {
            return Err(CONFLICT);
        }
        if record.certificate_sha256.as_ref() != Some(&receipt.certificate_sha256) {
            if record.phase != "ready"
                || record.certificate_sha256.as_ref() != receipt.binding.predecessor_sha256.as_ref()
            {
                return Err(CONFLICT);
            }
            record.certificate_sha256 = Some(receipt.certificate_sha256.clone());
            self.save("identity.json", &record.encode()?, true)?;
            cut_point!("record_saved");
        }
        let installed = self.facts(&record, &self.read("device.pem")?)?;
        if installed.fingerprint != receipt.certificate_sha256 {
            return Err(LOCAL_REFUSED);
        }
        let replace = self.read_online(COMPLETED)?.is_some();
        self.save(COMPLETED, &response.encode()?, replace)?;
        cut_point!("completed_saved");
        // Request first; the retained full response still recovers the cut
        // after this unlink. Only then the response transaction journal.
        if let Some(pending) = self.pending()? {
            if pending.binding != receipt.binding {
                return Err(CONFLICT);
            }
            self.remove(REQUEST)?;
            cut_point!("request_removed");
        }
        self.remove(RESPONSE)?;
        Ok(Completion {
            certificate_sha256: receipt.certificate_sha256.clone(),
            not_before_unix_secs: receipt.not_before_unix_secs,
            not_after_unix_secs: receipt.not_after_unix_secs,
            valid_now: now >= receipt.not_before_unix_secs && now < receipt.not_after_unix_secs,
        })
    }

    /// Finish a previously verified saved response, before any network
    /// request (`resume_online_response`). None without a saved response.
    pub(crate) fn resume_response(&self, now: u64) -> JResult<Option<Completion>> {
        self.response(RESPONSE)?
            .map(|response| self.finish_response(&response, now))
            .transpose()
    }

    /// The installed certificate's window and the journal (`online_status`).
    pub(crate) fn status(&self, now: u64) -> JResult<Status> {
        let record = self.record()?;
        if record.phase != "ready" {
            return Err(LOCAL_REFUSED);
        }
        self.profile()?;
        self.validate_prepared(&record)?;
        let (active, parked_refused) = match self.active(&record) {
            Ok(active) => (active, false),
            Err(PARKED_REFUSED) => (None, true),
            Err(code) => return Err(code),
        };
        if let Some((Leaf::Request, pending)) = &active {
            self.validate_pending(&record, pending)?;
        }
        let response = self.response(RESPONSE)?;
        if let Some(response) = &response {
            self.validate_response(&record, response, now, true)?;
        }
        let facts = self.facts(&record, &self.read("device.pem")?)?;
        if record.certificate_sha256.as_ref() != Some(&facts.fingerprint) {
            return Err(LOCAL_REFUSED);
        }
        let journaled = matches!(active, Some((Leaf::Request, _)));
        Ok(Status {
            not_before_unix_secs: facts.not_before_unix_secs,
            not_after_unix_secs: facts.not_after_unix_secs,
            pending: journaled || response.is_some(),
            recoverable: active.as_ref().is_some_and(|(_, pending)| {
                pending.binding.predecessor_sha256.as_ref() == Some(&facts.fingerprint)
            }),
            parked: matches!(active, Some((Leaf::Parked, _))),
            parked_refused,
        })
    }

    /// Resume the active Renew request (v32: the journaled one, else a
    /// parked one of the installed certificate), or durably write a new one
    /// (`begin_online_request(Renew)`): only for the ready, installed,
    /// currently due and unexpired predecessor, with a fresh request id
    /// (v32: never beside an unreadable parked request).
    pub(crate) fn begin_renew(&self, now: u64) -> JResult<RequestMaterial> {
        let record = self.record()?;
        self.profile()?;
        if now == 0 {
            return Err(LOCAL_REFUSED);
        }
        let pending = if let Some((_, pending)) = self.active(&record)? {
            self.validate_pending(&record, &pending)?;
            pending
        } else {
            if self.read_online(RESPONSE)?.is_some() {
                return Err(CONFLICT);
            }
            self.validate_prepared(&record)?;
            if record.phase != "ready" {
                return Err(LOCAL_REFUSED);
            }
            let certificate = self.read("device.pem")?;
            let facts = self.facts(&record, &certificate)?;
            if record.certificate_sha256.as_ref() != Some(&facts.fingerprint) {
                return Err(LOCAL_REFUSED);
            }
            if now >= facts.not_after_unix_secs {
                return Err(PREDECESSOR_EXPIRED);
            }
            let due = crate::identity_renewal::renewal_due_at(
                facts.not_before_unix_secs,
                facts.not_after_unix_secs,
            );
            if now < due {
                return Err(NOT_DUE);
            }
            let pending = Pending {
                binding: RequestBinding {
                    operation: Operation::Renew,
                    request_id: enrollment::new_invitation_token().to_string(),
                    profile_sha256: self.profile_sha256.clone(),
                    csr_sha256: sha(&self.read("device.csr")?),
                    predecessor_sha256: Some(facts.fingerprint),
                },
                predecessor_certificate_pem: Some(
                    local(std::str::from_utf8(&certificate))?.to_owned(),
                ),
            };
            self.validate_pending(&record, &pending)?;
            self.save(REQUEST, &pending.encode()?, false)?;
            pending
        };
        Ok(RequestMaterial {
            binding: pending.binding.clone(),
            csr_pem: local(std::str::from_utf8(&self.read("device.csr")?))?.to_owned(),
            predecessor_certificate_pem: pending.predecessor_certificate_pem.clone(),
        })
    }

    /// Sign the connection challenge for the active request
    /// (`sign_online_request`; v32: journaled or parked). Authorize needs a
    /// currently valid predecessor.
    pub(crate) fn sign(
        &self,
        binding: &RequestBinding,
        challenge: &ChallengeMessage,
        purpose: ProofPurpose,
        now: u64,
    ) -> JResult<Vec<u8>> {
        let record = self.record()?;
        let (_, pending) = self.active(&record)?.ok_or(LOCAL_REFUSED)?;
        self.validate_pending(&record, &pending)?;
        if pending.binding != *binding {
            return Err(CONFLICT);
        }
        if purpose == ProofPurpose::Authorize {
            let predecessor = self.facts(
                &record,
                pending
                    .predecessor_certificate_pem
                    .as_deref()
                    .ok_or(LOCAL_REFUSED)?
                    .as_bytes(),
            )?;
            if now < predecessor.not_before_unix_secs || now >= predecessor.not_after_unix_secs {
                return Err(PREDECESSOR_EXPIRED);
            }
        }
        local(protocol::sign_proof(
            &self.read("device.key")?,
            challenge,
            binding,
            purpose,
            now,
        ))
    }

    /// Verify and durably save an issued receipt, then finish it
    /// (`accept_online_response`). A repeated delivery of the last completed
    /// receipt is answered from the installed identity.
    pub(crate) fn accept(&self, receipt: &EnrollmentReceipt, now: u64) -> JResult<Completion> {
        let record = self.record()?;
        if let Some(saved) = self.response(RESPONSE)? {
            if !saved.same_receipt(receipt) {
                return Err(CONFLICT);
            }
            return self.finish_response(&saved, now);
        }
        let Some(pending) = self.pending()? else {
            // v32: a parked request is unparked before its first byte, so
            // no receipt can answer it here.
            if matches!(self.active(&record)?, Some((Leaf::Parked, _))) {
                return Err(CONFLICT);
            }
            let saved = self.response(COMPLETED)?.ok_or(LOCAL_REFUSED)?;
            self.validate_response(&record, &saved, now, true)?;
            let installed = self.facts(&record, &self.read("device.pem")?)?;
            if !saved.same_receipt(receipt)
                || record.certificate_sha256.as_ref() != Some(&receipt.certificate_sha256)
                || installed.fingerprint != receipt.certificate_sha256
            {
                return Err(CONFLICT);
            }
            return Ok(Completion {
                certificate_sha256: receipt.certificate_sha256.clone(),
                not_before_unix_secs: receipt.not_before_unix_secs,
                not_after_unix_secs: receipt.not_after_unix_secs,
                valid_now: now >= receipt.not_before_unix_secs && now < receipt.not_after_unix_secs,
            });
        };
        self.validate_pending(&record, &pending)?;
        if pending.binding != receipt.binding {
            return Err(RECEIPT_BINDING);
        }
        let response = SavedResponse {
            receipt: receipt.clone(),
            predecessor_certificate_pem: pending.predecessor_certificate_pem.clone(),
        };
        self.validate_response(&record, &response, now, false)?;
        // v32: a parked request beside this journaled one names this
        // predecessor or an older certificate. The verified issuance for
        // this predecessor means the authority no longer lists it, so that
        // request can never be issued: removed before the first identity
        // write. v32 review: one that cannot be read is left in place, never
        // a reason to refuse the only successor the authority names (it
        // refuses only the successor's own renewal, `PARKED_REFUSED`).
        if let Ok(Some(_)) = self.parked_request() {
            self.remove(PARKED)?;
            cut_point!("stale_parked_removed");
        }
        self.save(RESPONSE, &response.encode()?, false)?;
        cut_point!("response_saved");
        self.finish_response(&response, now)
    }

    /// v32: make the parked request the journaled request again, before its
    /// first request byte: an exclusive rename of `PARKED` to
    /// `online-request.json`, the directory synced. Only for a parked
    /// request of the installed certificate with no journal beside it.
    pub(crate) fn unpark(&self) -> JResult<()> {
        let record = self.record()?;
        if self.read_online(RESPONSE)?.is_some()
            || !matches!(self.active(&record)?, Some((Leaf::Parked, _)))
        {
            return Err(CONFLICT);
        }
        self.rename_leaf(PARKED, REQUEST, false)?;
        cut_point!("unparked");
        Ok(())
    }

    /// v32: park the journaled request the authority rejected (Rejected or
    /// RecoveryRequired, never an issued answer): rename it to `PARKED`,
    /// the directory synced, so the installed certificate can be captured
    /// beside it. Never with a saved response (`CONFLICT`), and never over
    /// a parked request that names the installed certificate or cannot be
    /// read (`PARKED_REFUSED`): only over a stale one.
    pub(crate) fn park(&self) -> JResult<()> {
        let record = self.record()?;
        if self.read_online(RESPONSE)?.is_some() {
            return Err(CONFLICT);
        }
        let pending = self.pending()?.ok_or(CONFLICT)?;
        self.validate_pending(&record, &pending)?;
        let replace = match self.parked_request() {
            Ok(None) => false,
            Ok(Some(parked))
                if parked.binding.predecessor_sha256.is_some()
                    && parked.binding.predecessor_sha256 != record.certificate_sha256 =>
            {
                true
            }
            _ => return Err(PARKED_REFUSED),
        };
        cut_point!("park_begin");
        self.rename_leaf(REQUEST, PARKED, replace)?;
        cut_point!("parked");
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_access {
    //! Test-only views of the journal's encodings.
    pub(crate) fn record_round_trip(bytes: &[u8]) -> Option<Vec<u8>> {
        super::Record::parse(bytes).ok()?.encode().ok()
    }
    pub(crate) fn pending_parses(bytes: &[u8]) -> bool {
        super::Pending::parse(bytes).is_ok()
    }
}
