//! B-06 v45: the host's journal for one join (`aegis-ne-host --enroll`).
//!
//! This is the first-enrollment subset of aegis-client's binary-private
//! device Store, with the same files, bytes, checks and write order, held
//! under one `ProtectedIdentityStore` lock:
//! - `prepare` (`device_identity_store::prepare`): the record
//!   `initializing`, the pinned device CA, the device key created once in its
//!   final place, its CSR, the record `prepared`;
//! - `pin` (`device_bundle::pin_profile_digest`): `bundle-profile.sha256`,
//!   never overwritten;
//! - the Redeem journal (`device_identity_online.rs`: begin, sign, accept,
//!   finish, resume): `online-request.json` with the invitation, durable
//!   before the request's first byte; `online-response.json` only after the
//!   issued receipt verified against the held key, the pinned device CA and
//!   the profile pin; `device.pem` created; `identity.json` `ready`;
//!   `online-completed.json`; then the request and the response removed. A
//!   cut anywhere leaves either a prepared identity with a journal or a saved
//!   response that `resume_response` finishes exactly once.
//!
//! It exists here, like `renewal_journal` (whose record and receipt codecs
//! it shares), because the binary's writable Store is private to the
//! aegis-client binary and the menu app must not shell out to a CLI. The
//! shared change that moves that Store into the aegis-client library (one
//! implementation for every caller) is recorded for merge.
//!
//! The invitation is parsed only into zeroizing memory and every parsed JSON
//! string holding it is overwritten before it is dropped. Every refusal is a
//! stable code; none names a path or a byte of the Store.
use crate::renewal_journal::{
    facts_with, rename_exclusive, sha, Completion, Record, SavedResponse, COMPLETED, REQUEST,
    RESPONSE,
};
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
use std::{
    fs::{File, OpenOptions},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use zeroize::{Zeroize, Zeroizing};

pub(crate) type JResult<T> = Result<T, &'static str>;

/// A Store, record, pin, key, CSR or journal check failed.
pub(crate) const LOCAL: &str = "enroll_local_refused";
/// A journal write, rename, removal or directory sync failed.
pub(crate) const WRITE: &str = "enroll_journal_write";
/// Another join holds this staging Store's lock.
pub(crate) const BUSY: &str = "enroll_busy";
/// The staging identity belongs to another device, CA or profile, or holds
/// files no join writes.
pub(crate) const CONFLICT: &str = "enroll_staging_conflict";
/// A journaled request carries another invitation than this package.
pub(crate) const INVITATION_CONFLICT: &str = "enroll_invitation_conflict";
/// An issued receipt failed a check (binding, device, CSR, chain, metadata).
pub(crate) const RECEIPT_REFUSED: &str = "enroll_receipt_refused";
/// The issued certificate is not valid yet by our clock.
pub(crate) const NOT_YET_VALID: &str = "enroll_certificate_not_yet_valid";
/// The issued (or staged) certificate has expired by our clock.
pub(crate) const EXPIRED: &str = "enroll_certificate_expired";

/// Every code this module returns.
#[cfg(test)]
pub(crate) const CODES: [&str; 8] = [
    LOCAL,
    WRITE,
    BUSY,
    CONFLICT,
    INVITATION_CONFLICT,
    RECEIPT_REFUSED,
    NOT_YET_VALID,
    EXPIRED,
];

const PROFILE: &str = "bundle-profile.sha256";
const MIGRATION: &str = "online-profile-migration.json";
const LOCK: &str = ".lock";
const TEMP_PREFIX: &str = ".tmp-enroll-";
const MAX_ONLINE: usize = 256 * 1024;
/// The files `prepare` may find while the record is `initializing`.
const INITIALIZING: [&str; 5] = [
    LOCK,
    "identity.json",
    "device-ca.pem",
    "device.key",
    "device.csr",
];

/// The files of an issued staged identity, sorted.
const ISSUED: [&str; 8] = [
    LOCK,
    "bundle-profile.sha256",
    "device-ca.pem",
    "device.csr",
    "device.key",
    "device.pem",
    "identity.json",
    "online-completed.json",
];

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn local<T, E>(result: Result<T, E>) -> JResult<T> {
    result.map_err(|_| LOCAL)
}

fn written<T, E>(result: Result<T, E>) -> JResult<T> {
    result.map_err(|_| WRITE)
}

fn missing(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|error| error.kind() == io::ErrorKind::NotFound)
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

/// Overwrite every string of a parsed value before it is dropped.
fn scrub(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(scrub),
        Value::Object(map) => map.values_mut().for_each(scrub),
        _ => {}
    }
}

/// A Redeem `online-request.json` (the binary's `Pending`).
struct Pending {
    binding: RequestBinding,
    invitation: Zeroizing<String>,
}

impl Pending {
    fn parse(bytes: &[u8]) -> JResult<Self> {
        let mut value: Value = local(serde_json::from_slice(bytes))?;
        let parsed = (|| {
            let object = value.as_object_mut().ok_or(LOCAL)?;
            let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
            keys.sort_unstable();
            if keys
                != [
                    "binding",
                    "invitation",
                    "predecessor_certificate_pem",
                    "version",
                ]
                || object["version"].as_u64() != Some(1)
                || !object["predecessor_certificate_pem"].is_null()
            {
                return Err(LOCAL);
            }
            let invitation = match object.remove("invitation") {
                Some(Value::String(token)) => Zeroizing::new(token),
                _ => return Err(LOCAL),
            };
            let binding: RequestBinding = local(serde_json::from_value(
                object.remove("binding").ok_or(LOCAL)?,
            ))?;
            Ok(Self {
                binding,
                invitation,
            })
        })();
        scrub(&mut value);
        parsed
    }

    /// The binary's `serde_json::to_vec(&Pending)` bytes, field order kept.
    fn encode(&self) -> JResult<Zeroizing<Vec<u8>>> {
        let binding = local(serde_json::to_string(&self.binding))?;
        let invitation = Zeroizing::new(local(serde_json::to_string(self.invitation.as_str()))?);
        // Sized once: the buffer holding the token never reallocates.
        let mut text = Zeroizing::new(Vec::with_capacity(binding.len() + invitation.len() + 96));
        text.extend_from_slice(b"{\"version\":1,\"binding\":");
        text.extend_from_slice(binding.as_bytes());
        text.extend_from_slice(b",\"predecessor_certificate_pem\":null,\"invitation\":");
        text.extend_from_slice(invitation.as_bytes());
        text.push(b'}');
        Ok(text)
    }
}

/// What a Redeem request sends.
pub(crate) struct RedeemMaterial {
    pub(crate) binding: RequestBinding,
    pub(crate) csr_pem: String,
    pub(crate) invitation: Zeroizing<String>,
}

/// Where one staged identity stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stand {
    /// Prepared and pinned; no request was ever journaled.
    Prepared,
    /// A request is journaled: its receipt is asked for first.
    Pending,
    /// A verified response is saved: finished without the network.
    Responded,
    /// Issued and installed in the staging Store.
    Completed,
}

/// The protected staging Store lock plus this module's atomic writer.
pub(crate) struct EnrollJournal {
    store: ProtectedIdentityStore,
    directory: PathBuf,
}

impl EnrollJournal {
    /// Open the staging identity directory, creating it (0700) when absent;
    /// its parent must exist. The directory must be the caller's with no
    /// group or other permission; the Store lock is created 0600 and held.
    /// Leftover temporary files of an interrupted write of this module are
    /// removed (they are never a final leaf).
    pub(crate) fn open(directory: &Path) -> JResult<Self> {
        if !directory.is_absolute() {
            return Err(LOCAL);
        }
        match std::fs::DirBuilder::new().mode(0o700).create(directory) {
            Ok(()) => {
                if let Some(parent) = directory.parent() {
                    written(File::open(parent).and_then(|dir| dir.sync_all()))?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(_) => return Err(WRITE),
        }
        let meta = local(std::fs::symlink_metadata(directory))?;
        // SAFETY: geteuid has no preconditions.
        if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
            return Err(CONFLICT);
        }
        let directory = local(enrollment::trusted_parent(&directory.join("identity.json")))?;
        let lock = local(
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(directory.join(LOCK)),
        )?;
        let store = ProtectedIdentityStore::adopt(directory.clone(), lock).map_err(|error| {
            if busy(&error) {
                BUSY
            } else {
                LOCAL
            }
        })?;
        let journal = Self { store, directory };
        for name in journal.entries()? {
            if name.starts_with(TEMP_PREFIX) {
                let path = journal.directory.join(&name);
                if local(std::fs::symlink_metadata(&path))?.is_file() {
                    written(std::fs::remove_file(&path))?;
                }
            }
        }
        Ok(journal)
    }

    fn entries(&self) -> JResult<Vec<String>> {
        let mut names = Vec::new();
        for entry in local(std::fs::read_dir(&self.directory))? {
            let name = local(entry)?.file_name();
            names.push(name.to_str().ok_or(CONFLICT)?.to_owned());
        }
        names.sort();
        Ok(names)
    }

    fn read(&self, name: &str) -> JResult<Zeroizing<Vec<u8>>> {
        local(self.store.read(name))
    }

    /// `None` when `name` is absent.
    fn read_optional(&self, name: &str) -> JResult<Option<Zeroizing<Vec<u8>>>> {
        match self.store.read(name) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if missing(&error) => Ok(None),
            Err(_) => Err(LOCAL),
        }
    }

    fn read_online(&self, name: &str) -> JResult<Option<Zeroizing<Vec<u8>>>> {
        match self.store.read_online(name) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(error) if missing(&error) => Ok(None),
            Err(_) => Err(LOCAL),
        }
    }

    fn pending(&self) -> JResult<Option<Pending>> {
        self.read_online(REQUEST)?
            .map(|bytes| Pending::parse(&bytes))
            .transpose()
    }

    fn response(&self, name: &str) -> JResult<Option<SavedResponse>> {
        self.read_online(name)?
            .map(|bytes| SavedResponse::parse(&bytes).map_err(|_| LOCAL))
            .transpose()
    }

    /// `Store::save`: a private temp file in the identity directory, synced,
    /// then renamed over (`replace`) or exclusively renamed into place, and
    /// the directory synced.
    fn save(&self, name: &str, bytes: &[u8], replace: bool) -> JResult<()> {
        if bytes.len() > MAX_ONLINE {
            return Err(LOCAL);
        }
        local(self.store.revalidate())?;
        let path = self.directory.join(name);
        if replace {
            local(validate_file(&local(std::fs::symlink_metadata(&path))?))?;
        }
        let staging = self.directory.join(format!(
            "{TEMP_PREFIX}{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let result = (|| {
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
        if result.is_err() {
            let _ = std::fs::remove_file(&staging);
        }
        written(result)?;
        self.sync_directory()?;
        local(self.store.revalidate())
    }

    /// The device key, created exactly once in its final place (never a
    /// staged secret that a cut could leave behind as "absent").
    fn create_key(&self, bytes: &[u8]) -> JResult<()> {
        local(self.store.revalidate())?;
        let mut key = written(
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
                .open(self.directory.join("device.key")),
        )?;
        self.sync_directory()?;
        written(key.write_all(bytes))?;
        written(key.sync_all())?;
        local(self.store.revalidate())
    }

    fn sync_directory(&self) -> JResult<()> {
        written(File::open(&self.directory).and_then(|dir| dir.sync_all()))
    }

    fn remove(&self, name: &str) -> JResult<()> {
        self.read_online(name)?.ok_or(LOCAL)?;
        written(std::fs::remove_file(self.directory.join(name)))?;
        self.sync_directory()
    }

    fn record_optional(&self) -> JResult<Option<Record>> {
        self.read_optional("identity.json")?
            .map(|bytes| Record::parse(&bytes).map_err(|_| LOCAL))
            .transpose()
    }

    fn record(&self) -> JResult<Record> {
        self.record_optional()?.ok_or(LOCAL)
    }

    fn pinned_ca(&self, record: &Record) -> JResult<Vec<u8>> {
        let ca = self.read("device-ca.pem")?;
        if sha(&ca) != record.device_ca_sha256 {
            return Err(LOCAL);
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
            return Err(LOCAL);
        }
        Ok(())
    }

    fn facts(&self, record: &Record, certificate: &[u8]) -> JResult<ValidatedDeviceCertificate> {
        let ca = self.pinned_ca(record)?;
        facts_with(record, &ca, &self.read("device.key")?, certificate)
    }

    /// The binary's `prepare` for `device_id` under `device_ca` (the bundle's
    /// device CA): resumable, never replacing a key, a CSR or another
    /// device's record.
    pub(crate) fn prepare(&self, device_id: &str, device_ca: &[u8]) -> JResult<()> {
        local(registry::validate_device_id(device_id))?;
        local(enrollment::validate_device_ca(device_ca))?;
        let mut record = match self.record_optional()? {
            Some(record) => record,
            None => {
                // An unrecorded key is never overwritten or adopted.
                if self.entries()? != [LOCK] {
                    return Err(CONFLICT);
                }
                let record = Record {
                    device_id: device_id.to_owned(),
                    phase: "initializing".into(),
                    device_ca_sha256: sha(device_ca),
                    certificate_sha256: None,
                };
                self.save("identity.json", &record.encode()?, false)?;
                record
            }
        };
        if record.device_id != device_id || record.device_ca_sha256 != sha(device_ca) {
            return Err(CONFLICT);
        }
        if record.phase == "initializing" {
            if self
                .entries()?
                .iter()
                .any(|name| !INITIALIZING.contains(&name.as_str()))
            {
                return Err(CONFLICT);
            }
            match self.read_optional("device-ca.pem")? {
                Some(existing) if existing.as_slice() == device_ca => {}
                Some(_) => return Err(CONFLICT),
                None => self.save("device-ca.pem", device_ca, false)?,
            }
            if self.read_optional("device.key")?.is_none() {
                if self.directory.join("device.csr").exists()
                    || self.directory.join("device.pem").exists()
                {
                    return Err(CONFLICT);
                }
                let material = local(enrollment::generate_csr(device_id))?;
                self.create_key(material.private_key_pem.as_bytes())?;
            }
            let key = self.read("device.key")?;
            let csr = local(enrollment::csr_for_key(
                device_id,
                local(std::str::from_utf8(&key))?,
            ))?;
            match self.read_optional("device.csr")? {
                Some(existing) if existing.as_slice() == csr.as_bytes() => {}
                Some(_) => return Err(CONFLICT),
                None => self.save("device.csr", csr.as_bytes(), false)?,
            }
            record.phase = "prepared".into();
            self.save("identity.json", &record.encode()?, true)?;
        }
        self.validate_prepared(&record)
    }

    /// `bundle-profile.sha256`: written once, never replaced; an existing
    /// pin must be exactly `profile_sha256`.
    pub(crate) fn pin(&self, profile_sha256: &str) -> JResult<()> {
        local(protocol::digest(profile_sha256))?;
        match self.read_optional(PROFILE)? {
            Some(existing) if existing.as_slice() == profile_sha256.as_bytes() => Ok(()),
            Some(_) => Err(CONFLICT),
            None => {
                self.save(PROFILE, profile_sha256.as_bytes(), false)?;
                if self.read(PROFILE)?.as_slice() != profile_sha256.as_bytes() {
                    return Err(LOCAL);
                }
                Ok(())
            }
        }
    }

    fn profile(&self, profile_sha256: &str) -> JResult<()> {
        if self.read(PROFILE)?.as_slice() != profile_sha256.as_bytes()
            || self.read_online(MIGRATION)?.is_some()
        {
            return Err(LOCAL);
        }
        Ok(())
    }

    fn validate_pending(
        &self,
        record: &Record,
        pending: &Pending,
        profile_sha256: &str,
    ) -> JResult<()> {
        local(pending.binding.validate())?;
        local(protocol::digest(&pending.invitation))?;
        if pending.binding.operation != Operation::Redeem
            || pending.binding.profile_sha256 != profile_sha256
        {
            return Err(LOCAL);
        }
        self.profile(profile_sha256)?;
        self.validate_prepared(record)?;
        if sha(&self.read("device.csr")?) != pending.binding.csr_sha256 {
            return Err(LOCAL);
        }
        if record.phase != "prepared" && self.read_online(RESPONSE)?.is_none() {
            return Err(CONFLICT);
        }
        Ok(())
    }

    fn validate_response(
        &self,
        record: &Record,
        response: &SavedResponse,
        profile_sha256: &str,
        now: u64,
        history: bool,
    ) -> JResult<()> {
        let receipt = &response.receipt;
        receipt.validate().map_err(|_| RECEIPT_REFUSED)?;
        if receipt.binding.operation != Operation::Redeem
            || receipt.binding.profile_sha256 != profile_sha256
            || receipt.binding.predecessor_sha256.is_some()
            || response.predecessor_certificate_pem.is_some()
        {
            return Err(RECEIPT_REFUSED);
        }
        self.profile(profile_sha256)?;
        self.validate_prepared(record)?;
        if receipt.device_id != record.device_id
            || receipt.binding.csr_sha256 != sha(&self.read("device.csr")?)
        {
            return Err(RECEIPT_REFUSED);
        }
        let ca = self.pinned_ca(record)?;
        let key = self.read("device.key")?;
        let signed = facts_with(record, &ca, &key, receipt.certificate_pem.as_bytes())
            .map_err(|_| RECEIPT_REFUSED)?;
        if signed.fingerprint != receipt.certificate_sha256
            || signed.not_before_unix_secs != receipt.not_before_unix_secs
            || signed.not_after_unix_secs != receipt.not_after_unix_secs
        {
            return Err(RECEIPT_REFUSED);
        }
        if !history && now >= signed.not_after_unix_secs {
            return Err(EXPIRED);
        }
        if !history && now < signed.not_before_unix_secs {
            return Err(NOT_YET_VALID);
        }
        Ok(())
    }

    /// Where the staged identity stands (after `prepare` and `pin`).
    pub(crate) fn stand(&self, profile_sha256: &str) -> JResult<Stand> {
        let record = self.record()?;
        self.profile(profile_sha256)?;
        self.validate_prepared(&record)?;
        if self.read_online(RESPONSE)?.is_some() {
            return Ok(Stand::Responded);
        }
        if let Some(pending) = self.pending()? {
            self.validate_pending(&record, &pending, profile_sha256)?;
            return Ok(Stand::Pending);
        }
        match record.phase.as_str() {
            "prepared" if !self.directory.join("device.pem").exists() => Ok(Stand::Prepared),
            "ready" => Ok(Stand::Completed),
            _ => Err(CONFLICT),
        }
    }

    /// The journaled request, if any, validated and carrying exactly
    /// `invitation`.
    pub(crate) fn journaled(
        &self,
        profile_sha256: &str,
        invitation: &str,
    ) -> JResult<Option<RedeemMaterial>> {
        let record = self.record()?;
        let Some(pending) = self.pending()? else {
            return Ok(None);
        };
        self.validate_pending(&record, &pending, profile_sha256)?;
        if !constant_eq(pending.invitation.as_bytes(), invitation.as_bytes()) {
            return Err(INVITATION_CONFLICT);
        }
        Ok(Some(RedeemMaterial {
            binding: pending.binding.clone(),
            csr_pem: local(std::str::from_utf8(&self.read("device.csr")?))?.to_owned(),
            invitation: pending.invitation,
        }))
    }

    /// Resume the journaled request (same invitation only), or durably
    /// write a new one for this prepared identity with a fresh request id
    /// (`begin_online_request(Redeem)`), before its first byte.
    pub(crate) fn begin_redeem(
        &self,
        profile_sha256: &str,
        invitation: &str,
    ) -> JResult<RedeemMaterial> {
        if let Some(material) = self.journaled(profile_sha256, invitation)? {
            return Ok(material);
        }
        let record = self.record()?;
        self.profile(profile_sha256)?;
        if self.read_online(RESPONSE)?.is_some() {
            return Err(CONFLICT);
        }
        self.validate_prepared(&record)?;
        if record.phase != "prepared" || self.directory.join("device.pem").exists() {
            return Err(CONFLICT);
        }
        local(protocol::digest(invitation))?;
        let pending = Pending {
            binding: RequestBinding {
                operation: Operation::Redeem,
                request_id: enrollment::new_invitation_token().to_string(),
                profile_sha256: profile_sha256.to_owned(),
                csr_sha256: sha(&self.read("device.csr")?),
                predecessor_sha256: None,
            },
            invitation: Zeroizing::new(invitation.to_owned()),
        };
        self.validate_pending(&record, &pending, profile_sha256)?;
        self.save(REQUEST, &pending.encode()?, false)?;
        Ok(RedeemMaterial {
            binding: pending.binding.clone(),
            csr_pem: local(std::str::from_utf8(&self.read("device.csr")?))?.to_owned(),
            invitation: Zeroizing::new(invitation.to_owned()),
        })
    }

    /// Sign the connection challenge for the journaled request
    /// (`sign_online_request`).
    pub(crate) fn sign(
        &self,
        profile_sha256: &str,
        binding: &RequestBinding,
        challenge: &ChallengeMessage,
        purpose: ProofPurpose,
        now: u64,
    ) -> JResult<Vec<u8>> {
        let record = self.record()?;
        let pending = self.pending()?.ok_or(LOCAL)?;
        self.validate_pending(&record, &pending, profile_sha256)?;
        if pending.binding != *binding {
            return Err(CONFLICT);
        }
        local(protocol::sign_proof(
            &self.read("device.key")?,
            challenge,
            binding,
            purpose,
            now,
        ))
    }

    fn finish_response(
        &self,
        response: &SavedResponse,
        profile_sha256: &str,
        now: u64,
    ) -> JResult<Completion> {
        let mut record = self.record()?;
        self.validate_response(&record, response, profile_sha256, now, true)?;
        let receipt = &response.receipt;
        if let Some(pending) = self.pending()? {
            self.validate_pending(&record, &pending, profile_sha256)?;
            if pending.binding != receipt.binding {
                return Err(CONFLICT);
            }
        }
        match self.read_optional("device.pem")? {
            Some(existing) => {
                let current = self.facts(&record, &existing)?;
                if current.fingerprint != receipt.certificate_sha256
                    || existing.as_slice() != receipt.certificate_pem.as_bytes()
                {
                    return Err(CONFLICT);
                }
            }
            None => {
                if record.phase != "prepared" || record.certificate_sha256.is_some() {
                    return Err(CONFLICT);
                }
                self.save("device.pem", receipt.certificate_pem.as_bytes(), false)?;
            }
        }
        if record.certificate_sha256.as_ref() != Some(&receipt.certificate_sha256) {
            if record.phase != "prepared" || record.certificate_sha256.is_some() {
                return Err(CONFLICT);
            }
            record.phase = "ready".into();
            record.certificate_sha256 = Some(receipt.certificate_sha256.clone());
            self.save("identity.json", &record.encode()?, true)?;
        }
        let installed = self.facts(&record, &self.read("device.pem")?)?;
        if installed.fingerprint != receipt.certificate_sha256 {
            return Err(LOCAL);
        }
        let replace = self.read_online(COMPLETED)?.is_some();
        self.save(COMPLETED, &response.encode()?, replace)?;
        // The request (and its invitation) first; the retained response
        // still recovers a cut after this unlink.
        if let Some(pending) = self.pending()? {
            if pending.binding != receipt.binding {
                return Err(CONFLICT);
            }
            self.remove(REQUEST)?;
        }
        self.remove(RESPONSE)?;
        Ok(completion(receipt, now))
    }

    /// Finish a previously verified saved response before any network
    /// request (`resume_online_response`).
    pub(crate) fn resume_response(
        &self,
        profile_sha256: &str,
        now: u64,
    ) -> JResult<Option<Completion>> {
        self.response(RESPONSE)?
            .map(|response| self.finish_response(&response, profile_sha256, now))
            .transpose()
    }

    /// Verify and durably save an issued receipt for the journaled request,
    /// then finish it (`accept_online_response`).
    pub(crate) fn accept(
        &self,
        profile_sha256: &str,
        receipt: &EnrollmentReceipt,
        now: u64,
    ) -> JResult<Completion> {
        let record = self.record()?;
        if let Some(saved) = self.response(RESPONSE)? {
            if !saved.same_receipt(receipt) {
                return Err(CONFLICT);
            }
            return self.finish_response(&saved, profile_sha256, now);
        }
        let pending = self.pending()?.ok_or(LOCAL)?;
        self.validate_pending(&record, &pending, profile_sha256)?;
        if pending.binding != receipt.binding {
            return Err(RECEIPT_REFUSED);
        }
        let response = SavedResponse {
            receipt: receipt.clone(),
            predecessor_certificate_pem: None,
        };
        self.validate_response(&record, &response, profile_sha256, now, false)?;
        self.save(RESPONSE, &response.encode()?, false)?;
        self.finish_response(&response, profile_sha256, now)
    }

    /// The finished staged identity, as the provider's import will judge
    /// it: ready, no journal, the completed receipt of the installed
    /// certificate, currently valid (the library's `ProtectedOnlineExpectation`
    /// over this same held lock).
    pub(crate) fn completed(&self, profile_sha256: &str, now: u64) -> JResult<Completion> {
        let record = self.record()?;
        if record.phase != "ready" {
            return Err(LOCAL);
        }
        // Exactly the issued identity: no sidecar or stray file rides along
        // into the import.
        if self.entries()? != ISSUED {
            return Err(CONFLICT);
        }
        self.profile(profile_sha256)?;
        for name in [REQUEST, RESPONSE, MIGRATION] {
            if self.read_online(name)?.is_some() {
                return Err(CONFLICT);
            }
        }
        let installed = self.facts(&record, &self.read("device.pem")?)?;
        if record.certificate_sha256.as_ref() != Some(&installed.fingerprint) {
            return Err(LOCAL);
        }
        if now >= installed.not_after_unix_secs {
            return Err(EXPIRED);
        }
        if now < installed.not_before_unix_secs {
            return Err(NOT_YET_VALID);
        }
        let saved = self.response(COMPLETED)?.ok_or(LOCAL)?;
        self.validate_response(&record, &saved, profile_sha256, now, true)?;
        if saved.receipt.certificate_sha256 != installed.fingerprint {
            return Err(LOCAL);
        }
        let expected = local(ProtectedOnlineExpectation::from_held(
            &self.store,
            profile_sha256,
        ))?;
        let expectation = local(expected.expectation_at(now))?;
        if expectation.certificate_sha256 != installed.fingerprint {
            return Err(LOCAL);
        }
        Ok(completion(&saved.receipt, now))
    }
}

fn completion(receipt: &EnrollmentReceipt, now: u64) -> Completion {
    Completion {
        certificate_sha256: receipt.certificate_sha256.clone(),
        not_before_unix_secs: receipt.not_before_unix_secs,
        not_after_unix_secs: receipt.not_after_unix_secs,
        valid_now: now >= receipt.not_before_unix_secs && now < receipt.not_after_unix_secs,
    }
}

/// Equal length and bytes, without an early exit on the first difference.
fn constant_eq(left: &[u8], right: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    left.len() == right.len() && bool::from(left.ct_eq(right))
}

#[cfg(test)]
pub(crate) mod test_access {
    //! Test-only views of the request encoding.
    pub(crate) fn pending_round_trip(bytes: &[u8]) -> Option<Vec<u8>> {
        Some(super::Pending::parse(bytes).ok()?.encode().ok()?.to_vec())
    }
}
