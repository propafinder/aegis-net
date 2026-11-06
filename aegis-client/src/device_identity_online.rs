//! Durable online enrollment transitions under the existing identity lock.
//! The device key is immutable; only a validated same-key successor can replace
//! the expected predecessor. No response grants a claim of fleet distribution.
use super::*;
use aegis_client::online_expectation::OnlineExpectation;
use aegis_core::secure_channel::{
    enrollment::protocol::{self, ChallengeMessage, Operation, ProofPurpose, RequestBinding},
    enrollment_wire::EnrollmentReceipt,
};
use zeroize::{Zeroize, Zeroizing};

const REQUEST: &str = "online-request.json";
const RESPONSE: &str = "online-response.json";
const COMPLETED: &str = "online-completed.json";
const MIGRATION: &str = "online-profile-migration.json";
const PROFILE: &str = "bundle-profile.sha256";
const MAX_ONLINE: u64 = 256 * 1024;

#[cfg(unix)]
#[path = "device_identity_refresh.rs"]
mod refresh;
#[cfg(unix)]
pub(crate) use refresh::{prepare_refresh, replace_refresh_invitation, RefreshSnapshot};

#[cfg(all(test, windows))]
mod windows_storage_tests {
    use super::*;

    #[test]
    fn online_state_preserves_acl_bounds_and_rejects_hard_links() {
        let parent = PathBuf::from(std::env::var_os("ProgramData").unwrap());
        let root = tempfile::Builder::new()
            .prefix("AEGIS-online-state-test-")
            .tempdir_in(parent)
            .unwrap();
        let store = Store::open(&root.path().join("identity"), true).unwrap();
        let first = serde_json::json!({"fixture": "first"});
        let next = serde_json::json!({"fixture": "replacement"});
        save_large(&store, REQUEST, &first, false).unwrap();
        assert!(save_large(&store, REQUEST, &next, false).is_err());
        assert_eq!(
            optional::<serde_json::Value>(&store, REQUEST).unwrap(),
            Some(first)
        );
        save_large(&store, REQUEST, &next, true).unwrap();
        assert_eq!(
            optional::<serde_json::Value>(&store, REQUEST).unwrap(),
            Some(next.clone())
        );
        let alias = store.path("hard-link.json");
        fs::hard_link(store.path(REQUEST), &alias).unwrap();
        assert!(read_large(&store, REQUEST).is_err());
        assert!(save_large(&store, REQUEST, &next, true).is_err());
        assert!(remove(&store, REQUEST).is_err());
        fs::remove_file(alias).unwrap();
        let oversized = "x".repeat(MAX_ONLINE as usize);
        assert!(save_large(&store, REQUEST, &oversized, true).is_err());
        assert_eq!(
            optional::<serde_json::Value>(&store, REQUEST).unwrap(),
            Some(next)
        );
        remove(&store, REQUEST).unwrap();
        assert!(optional::<serde_json::Value>(&store, REQUEST)
            .unwrap()
            .is_none());
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u8,
    binding: RequestBinding,
    predecessor_certificate_pem: Option<String>,
    invitation: Option<String>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some(value) = &mut self.invitation {
            value.zeroize();
        }
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedResponse {
    version: u8,
    receipt: EnrollmentReceipt,
    predecessor_certificate_pem: Option<String>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Migration {
    version: u8,
    old_sha256: String,
    new_sha256: String,
}

pub(crate) struct RequestMaterial {
    pub binding: RequestBinding,
    pub csr_pem: String,
    pub predecessor_certificate_pem: Option<String>,
    pub invitation: Option<Zeroizing<String>>,
    pub resume: bool,
}
#[derive(Serialize)]
pub(crate) struct LocalCompletion {
    pub device_id: String,
    pub certificate_sha256: String,
    pub not_after_unix_secs: u64,
    pub certificate_valid_now: bool,
    pub state: &'static str,
}
#[derive(Serialize)]
pub(crate) struct OnlineStatus {
    pub device_id: String,
    pub state: &'static str,
    pub not_before_unix_secs: Option<u64>,
    pub not_after_unix_secs: Option<u64>,
    pub renewal_due: bool,
    pub pending: bool,
}

#[derive(Serialize)]
pub(crate) struct LocalRecovery {
    pub schema: &'static str,
    /// `runtime_recovery_required` permits only managed receipt recovery. It
    /// is never a readiness or current certificate authorization assertion.
    pub phase: &'static str,
    pub repaired: bool,
    pub pending_request: bool,
}

/// Installer-local recovery of an existing pinned identity. Every expectation
/// is checked before changing a journal or certificate, under the same lock.
/// This path cannot create a key, request, pin or network connection.
pub(crate) fn recover_local(
    directory: &Path,
    bundle: &Path,
    expected_device_id: &str,
    now: u64,
) -> Result<LocalRecovery> {
    registry::validate_device_id(expected_device_id)?;
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    ensure!(
        record.device_id == expected_device_id,
        "device identity differs from recovery request"
    );
    let public = crate::device_bundle::online::OnlineProfile::load(bundle, &store.directory)?;
    profile(&store, public.digest())?;
    ensure!(
        sha(&public_input(&bundle.join("device-ca.pem"))?) == record.device_ca_sha256,
        "public profile CA differs from the existing device identity"
    );
    validate_prepared(&store, &record)?;
    ensure!(
        matches!(record.phase.as_str(), "prepared" | "ready"),
        "finish device preparation before local recovery"
    );
    let pending: Option<Pending> = optional(&store, REQUEST)?;
    if let Some(pending) = &pending {
        validate_pending(&store, &record, pending)?;
    }
    if let Some(response) = optional::<SavedResponse>(&store, RESPONSE)? {
        // Unlike the explicit historical status repair, installer recovery
        // requires a currently valid successor before making any changes.
        validate_response(&store, &record, &response, now, false)?;
        let completion = finish_response(&store, &response, now)?;
        ensure!(
            completion.certificate_valid_now,
            "recovered certificate is not currently valid"
        );
        return Ok(LocalRecovery {
            schema: "aegis_device_local_recovery_v1",
            phase: "ready",
            repaired: true,
            pending_request: false,
        });
    }
    let phase = if record.phase == "prepared" {
        "prepared"
    } else {
        let current = facts(&store, &record, &store.read("device.pem")?)?;
        ensure!(
            record.certificate_sha256.as_ref() == Some(&current.fingerprint),
            "installed certificate record changed; local response missing"
        );
        if now >= current.not_before_unix_secs && now < current.not_after_unix_secs {
            "ready"
        } else {
            // The authority may already have committed a response before
            // expiry. Only the managed runtime can recover it with fresh PoP;
            // the installer must not renew or redeem from its unbound shell.
            let recoverable = pending.as_ref().is_some_and(|pending| {
                pending.binding.operation == Operation::Renew
                    && pending.binding.predecessor_sha256.as_ref() == Some(&current.fingerprint)
            });
            ensure!(
                now >= current.not_after_unix_secs && recoverable,
                "device certificate is not currently valid and has no recoverable renewal request"
            );
            "runtime_recovery_required"
        }
    };
    Ok(LocalRecovery {
        schema: "aegis_device_local_recovery_v1",
        phase,
        repaired: false,
        pending_request: pending.is_some(),
    })
}

fn read_large(store: &Store, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let path = store.path(name);
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options.open(path)?;
    #[cfg(windows)]
    if store.machine {
        aegis_core::windows_file::validate_machine_private(&file)?;
    } else {
        aegis_core::windows_file::validate_private(&file, false)?;
    }
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_ONLINE,
        "online identity state exceeds bound"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        ensure!(
            metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0
                && metadata.nlink() == 1,
            "online identity state permissions or links invalid"
        );
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(MAX_ONLINE + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_ONLINE,
        "online identity state exceeds bound"
    );
    Ok(bytes)
}
fn optional<T: serde::de::DeserializeOwned>(store: &Store, name: &str) -> Result<Option<T>> {
    match read_large(store, name) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("online identity state invalid")?,
        )),
        Err(e) if is_missing(&e) => Ok(None),
        Err(e) => Err(e),
    }
}
fn save_large(store: &Store, name: &str, value: &impl Serialize, replace: bool) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value)?);
    ensure!(
        bytes.len() as u64 <= MAX_ONLINE,
        "online identity state exceeds bound"
    );
    if replace {
        read_large(store, name)?;
    }
    store.save(name, &bytes, replace)
}
fn remove(store: &Store, name: &str) -> Result<()> {
    read_large(store, name)?;
    fs::remove_file(store.path(name))?;
    aegis_core::secret_file::sync_directory(&store.directory)?;
    Ok(())
}
fn profile(store: &Store, expected: &str) -> Result<()> {
    protocol::digest(expected)?;
    ensure!(
        std::str::from_utf8(&store.read(PROFILE)?)?.trim() == expected,
        "online profile does not match the durable identity pin"
    );
    ensure!(
        optional::<Migration>(store, MIGRATION)?.is_none(),
        "profile migration requires exact recovery"
    );
    Ok(())
}
fn facts(
    store: &Store,
    record: &Record,
    certificate: &[u8],
) -> Result<enrollment::ValidatedDeviceCertificate> {
    let ca = pinned_ca(store, record)?;
    let facts = enrollment::device_certificate_metadata(&record.device_id, certificate, &ca)?;
    enrollment::validate_device_certificate(
        &record.device_id,
        certificate,
        &ca,
        &store.read("device.key")?,
        facts.not_before_unix_secs,
    )?;
    Ok(facts)
}
fn validate_pending(store: &Store, record: &Record, pending: &Pending) -> Result<()> {
    ensure!(pending.version == 1, "online request version invalid");
    pending.binding.validate()?;
    profile(store, &pending.binding.profile_sha256)?;
    validate_prepared(store, record)?;
    ensure!(
        sha(&store.read("device.csr")?) == pending.binding.csr_sha256,
        "pending CSR binding changed"
    );
    match pending.binding.operation {
        Operation::Redeem => {
            ensure!(
                pending.predecessor_certificate_pem.is_none(),
                "initial request has predecessor"
            );
            protocol::digest(
                pending
                    .invitation
                    .as_deref()
                    .context("pending invitation missing")?,
            )?;
            ensure!(
                record.phase == "prepared" || optional::<SavedResponse>(store, RESPONSE)?.is_some(),
                "initial request cannot replace an existing identity"
            );
        }
        Operation::Renew => {
            ensure!(
                pending.invitation.is_none(),
                "renewal cannot carry invitation"
            );
            let predecessor = pending
                .predecessor_certificate_pem
                .as_deref()
                .context("pending predecessor missing")?;
            let predecessor = facts(store, record, predecessor.as_bytes())?;
            ensure!(
                Some(&predecessor.fingerprint) == pending.binding.predecessor_sha256.as_ref(),
                "pending predecessor binding changed"
            );
            ensure!(record.phase == "ready", "renewal requires ready identity");
            if record.certificate_sha256.as_ref() != pending.binding.predecessor_sha256.as_ref() {
                let response: SavedResponse =
                    optional(store, RESPONSE)?.context("unrecorded certificate replacement")?;
                ensure!(
                    response.receipt.binding == pending.binding
                        && record.certificate_sha256.as_ref()
                            == Some(&response.receipt.certificate_sha256),
                    "unrecorded certificate replacement"
                );
            }
        }
    }
    Ok(())
}
fn token_input(path: &Path) -> Result<Zeroizing<String>> {
    enrollment::trusted_parent(path)?;
    let input = read_private(path)?;
    ensure!(input.len() <= 256, "invitation input exceeds bound");
    let token = Zeroizing::new(std::str::from_utf8(&input)?.trim().to_owned());
    protocol::digest(&token)?;
    Ok(token)
}

pub(super) fn ensure_idle(store: &Store) -> Result<()> {
    ensure!(
        optional::<Pending>(store, REQUEST)?.is_none()
            && optional::<SavedResponse>(store, RESPONSE)?.is_none()
            && optional::<Migration>(store, MIGRATION)?.is_none(),
        "finish the online identity transition before offline completion"
    );
    Ok(())
}

pub(crate) fn begin_online_request(
    directory: &Path,
    operation: Operation,
    profile_sha256: &str,
    invitation_file: Option<&Path>,
    now: u64,
) -> Result<RequestMaterial> {
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    profile(&store, profile_sha256)?;
    ensure!(now > 0, "online request clock invalid");
    let existing: Option<Pending> = optional(&store, REQUEST)?;
    let resume = existing.is_some();
    let pending = if let Some(pending) = existing {
        validate_pending(&store, &record, &pending)?;
        ensure!(
            pending.binding.operation == operation,
            "a different online operation is pending"
        );
        if let Some(path) = invitation_file {
            let token = token_input(path)?;
            ensure!(
                pending.invitation.as_deref() == Some(token.as_str()),
                "supplied invitation differs from durable pending request"
            );
        }
        pending
    } else {
        ensure!(
            optional::<SavedResponse>(&store, RESPONSE)?.is_none(),
            "complete the retained local response before starting another request"
        );
        validate_prepared(&store, &record)?;
        let (predecessor_sha256, predecessor_certificate_pem, invitation) = match operation {
            Operation::Redeem => {
                ensure!(
                    record.phase == "prepared" && !store.path("device.pem").try_exists()?,
                    "initial issuance requires an uncompleted identity"
                );
                let token = token_input(
                    invitation_file
                        .context("a protected invitation file is required for the first request")?,
                )?;
                (None, None, Some(token.to_string()))
            }
            Operation::Renew => {
                ensure!(
                    invitation_file.is_none() && record.phase == "ready",
                    "renewal requires ready identity without invitation"
                );
                let certificate = store.read("device.pem")?;
                let facts = facts(&store, &record, &certificate)?;
                ensure!(
                    record.certificate_sha256.as_ref() == Some(&facts.fingerprint),
                    "installed certificate record changed"
                );
                let due = facts.not_before_unix_secs
                    + (facts.not_after_unix_secs - facts.not_before_unix_secs) * 2 / 3;
                ensure!(
                    now >= due && now < facts.not_after_unix_secs,
                    "certificate renewal is not due or predecessor expired"
                );
                (
                    Some(facts.fingerprint),
                    Some(std::str::from_utf8(&certificate)?.to_owned()),
                    None,
                )
            }
        };
        let request_id = enrollment::new_invitation_token().to_string();
        let pending = Pending {
            version: 1,
            binding: RequestBinding {
                operation,
                request_id,
                profile_sha256: profile_sha256.to_owned(),
                csr_sha256: sha(&store.read("device.csr")?),
                predecessor_sha256,
            },
            predecessor_certificate_pem,
            invitation,
        };
        validate_pending(&store, &record, &pending)?;
        save_large(&store, REQUEST, &pending, false)?;
        pending
    };
    Ok(RequestMaterial {
        binding: pending.binding.clone(),
        csr_pem: std::str::from_utf8(&store.read("device.csr")?)?.to_owned(),
        predecessor_certificate_pem: pending.predecessor_certificate_pem.clone(),
        invitation: pending
            .invitation
            .as_ref()
            .map(|token| Zeroizing::new(token.clone())),
        resume,
    })
}

pub(crate) fn sign_online_request(
    directory: &Path,
    binding: &RequestBinding,
    challenge: &ChallengeMessage,
    purpose: ProofPurpose,
    now: u64,
) -> Result<Vec<u8>> {
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    let pending: Pending = optional(&store, REQUEST)?.context("online request not prepared")?;
    validate_pending(&store, &record, &pending)?;
    ensure!(
        pending.binding == *binding,
        "online request binding changed"
    );
    if purpose == ProofPurpose::Authorize && binding.operation == Operation::Renew {
        let predecessor = facts(
            &store,
            &record,
            pending
                .predecessor_certificate_pem
                .as_deref()
                .context("predecessor missing")?
                .as_bytes(),
        )?;
        ensure!(
            now >= predecessor.not_before_unix_secs && now < predecessor.not_after_unix_secs,
            "expired predecessor permits receipt recovery only"
        );
    }
    Ok(protocol::sign_proof(
        &store.read("device.key")?,
        challenge,
        binding,
        purpose,
        now,
    )?)
}

fn validate_response(
    store: &Store,
    record: &Record,
    response: &SavedResponse,
    now: u64,
    history: bool,
) -> Result<()> {
    ensure!(
        response.version == 1,
        "saved online response version invalid"
    );
    let receipt = &response.receipt;
    receipt.validate()?;
    profile(store, &receipt.binding.profile_sha256)?;
    validate_prepared(store, record)?;
    ensure!(
        receipt.device_id == record.device_id
            && receipt.binding.csr_sha256 == sha(&store.read("device.csr")?),
        "response identity or CSR does not match local request"
    );
    let signed = facts(store, record, receipt.certificate_pem.as_bytes())?;
    ensure!(
        signed.fingerprint == receipt.certificate_sha256
            && signed.not_before_unix_secs == receipt.not_before_unix_secs
            && signed.not_after_unix_secs == receipt.not_after_unix_secs,
        "response metadata does not match signed certificate"
    );
    if !history {
        ensure!(
            now >= signed.not_before_unix_secs && now < signed.not_after_unix_secs,
            "response certificate is not currently valid"
        );
    }
    match receipt.binding.operation {
        Operation::Redeem => ensure!(
            response.predecessor_certificate_pem.is_none(),
            "initial response has a predecessor"
        ),
        Operation::Renew => {
            let predecessor = facts(
                store,
                record,
                response
                    .predecessor_certificate_pem
                    .as_deref()
                    .context("response predecessor missing")?
                    .as_bytes(),
            )?;
            let due = predecessor.not_before_unix_secs
                + (predecessor.not_after_unix_secs - predecessor.not_before_unix_secs) * 2 / 3;
            ensure!(
                receipt.binding.predecessor_sha256.as_ref() == Some(&predecessor.fingerprint)
                    && signed.not_before_unix_secs >= due
                    && signed.not_before_unix_secs < predecessor.not_after_unix_secs
                    && signed.not_after_unix_secs > predecessor.not_after_unix_secs,
                "renewal response does not extend the expected valid predecessor"
            );
        }
    }
    Ok(())
}
fn finish_response(store: &Store, response: &SavedResponse, now: u64) -> Result<LocalCompletion> {
    let mut record = store.record()?;
    validate_response(store, &record, response, now, true)?;
    let receipt = &response.receipt;
    // Check both journals before replacing either certificate or metadata.
    // Cleanup-time detection would otherwise leave a partially advanced local
    // identity beside a conflicting request after storage corruption.
    if let Some(pending) = optional::<Pending>(store, REQUEST)? {
        validate_pending(store, &record, &pending)?;
        ensure!(
            pending.binding == receipt.binding
                && pending.predecessor_certificate_pem == response.predecessor_certificate_pem,
            "saved response conflicts with the pending local request"
        );
    }
    match store.read("device.pem") {
        Ok(existing) => {
            let current = facts(store, &record, &existing)?;
            if current.fingerprint != receipt.certificate_sha256 {
                ensure!(
                    receipt.binding.operation == Operation::Renew
                        && receipt.binding.predecessor_sha256.as_ref()
                            == Some(&current.fingerprint)
                        && record.certificate_sha256.as_ref() == Some(&current.fingerprint),
                    "only the expected predecessor can be replaced"
                );
                store.save("device.pem", receipt.certificate_pem.as_bytes(), true)?;
            } else {
                ensure!(
                    existing.as_slice() == receipt.certificate_pem.as_bytes(),
                    "successor encoding differs from durable response"
                );
            }
        }
        Err(error) if is_missing(&error) => {
            ensure!(
                receipt.binding.operation == Operation::Redeem
                    && record.phase == "prepared"
                    && record.certificate_sha256.is_none(),
                "missing prior certificate cannot be replaced automatically"
            );
            store.save("device.pem", receipt.certificate_pem.as_bytes(), false)?;
        }
        Err(error) => return Err(error),
    }
    if record.certificate_sha256.as_ref() != Some(&receipt.certificate_sha256) {
        ensure!(
            (receipt.binding.operation == Operation::Redeem
                && record.phase == "prepared"
                && record.certificate_sha256.is_none())
                || (receipt.binding.operation == Operation::Renew
                    && record.phase == "ready"
                    && record.certificate_sha256.as_ref()
                        == receipt.binding.predecessor_sha256.as_ref()),
            "identity record is not the expected predecessor"
        );
        record.phase = "ready".into();
        record.certificate_sha256 = Some(receipt.certificate_sha256.clone());
        store.save_record(&record, true)?;
    }
    let final_facts = facts(store, &record, &store.read("device.pem")?)?;
    ensure!(
        final_facts.fingerprint == receipt.certificate_sha256,
        "successor verification failed"
    );
    let completed: Option<SavedResponse> = optional(store, COMPLETED)?;
    save_large(store, COMPLETED, response, completed.is_some())?;
    // Request/token first; the retained full response still recovers the cut
    // after this unlink. Only then clear the response transaction journal.
    if let Some(pending) = optional::<Pending>(store, REQUEST)? {
        ensure!(
            pending.binding == receipt.binding,
            "request changed during completion"
        );
        remove(store, REQUEST)?;
    }
    remove(store, RESPONSE)?;
    Ok(completion(receipt, now))
}
fn completion(receipt: &EnrollmentReceipt, now: u64) -> LocalCompletion {
    LocalCompletion {
        device_id: receipt.device_id.clone(),
        certificate_sha256: receipt.certificate_sha256.clone(),
        not_after_unix_secs: receipt.not_after_unix_secs,
        certificate_valid_now: now >= receipt.not_before_unix_secs
            && now < receipt.not_after_unix_secs,
        state: "issued_pending_distribution",
    }
}

pub(crate) fn accept_online_response(
    directory: &Path,
    receipt: &EnrollmentReceipt,
    now: u64,
) -> Result<LocalCompletion> {
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    if let Some(saved) = optional::<SavedResponse>(&store, RESPONSE)? {
        ensure!(
            serde_json::to_vec(&saved.receipt)? == serde_json::to_vec(receipt)?,
            "response differs from retained completion"
        );
        return finish_response(&store, &saved, now);
    }
    let pending: Pending = match optional(&store, REQUEST)? {
        Some(pending) => pending,
        None => {
            let saved: SavedResponse =
                optional(&store, COMPLETED)?.context("no pending online request")?;
            validate_response(&store, &record, &saved, now, true)?;
            ensure!(
                serde_json::to_vec(&saved.receipt)? == serde_json::to_vec(receipt)?
                    && record.certificate_sha256.as_ref() == Some(&receipt.certificate_sha256),
                "response is not the last completed identity"
            );
            ensure!(
                facts(&store, &record, &store.read("device.pem")?)?.fingerprint
                    == receipt.certificate_sha256,
                "installed certificate differs from completed response"
            );
            return Ok(completion(receipt, now));
        }
    };
    validate_pending(&store, &record, &pending)?;
    ensure!(
        pending.binding == receipt.binding,
        "response binding differs from pending request"
    );
    let response = SavedResponse {
        version: 1,
        receipt: receipt.clone(),
        predecessor_certificate_pem: pending.predecessor_certificate_pem.clone(),
    };
    validate_response(&store, &record, &response, now, false)?;
    save_large(&store, RESPONSE, &response, false)?;
    finish_response(&store, &response, now)
}

/// Repair only a previously verified local response, before any new network
/// request. A response that expired during downtime completes state but reports
/// certificate_valid_now=false; it cannot activate traffic or authorize renew.
pub(crate) fn resume_online_response(
    directory: &Path,
    now: u64,
) -> Result<Option<LocalCompletion>> {
    let store = Store::open(directory, false)?;
    optional::<SavedResponse>(&store, RESPONSE)?
        .map(|response| finish_response(&store, &response, now))
        .transpose()
}

pub(crate) fn online_status(directory: &Path, now: u64) -> Result<OnlineStatus> {
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    validate_prepared(&store, &record)?;
    let pending: Option<Pending> = optional(&store, REQUEST)?;
    if let Some(pending) = &pending {
        validate_pending(&store, &record, pending)?;
    }
    let response: Option<SavedResponse> = optional(&store, RESPONSE)?;
    if let Some(response) = &response {
        validate_response(&store, &record, response, now, true)?;
    }
    let has_pending = pending.is_some() || response.is_some();
    if record.phase == "prepared" {
        return Ok(OnlineStatus {
            device_id: record.device_id,
            state: "prepared",
            not_before_unix_secs: None,
            not_after_unix_secs: None,
            renewal_due: false,
            pending: has_pending,
        });
    }
    ensure!(record.phase == "ready", "device preparation incomplete");
    let facts = facts(&store, &record, &store.read("device.pem")?)?;
    ensure!(
        record.certificate_sha256.as_ref() == Some(&facts.fingerprint),
        "installed certificate record changed; resume saved response"
    );
    let valid = now >= facts.not_before_unix_secs && now < facts.not_after_unix_secs;
    let due = facts.not_before_unix_secs
        + (facts.not_after_unix_secs - facts.not_before_unix_secs) * 2 / 3;
    Ok(OnlineStatus {
        device_id: record.device_id,
        state: if valid {
            "ready"
        } else if now >= facts.not_after_unix_secs {
            "expired"
        } else {
            "not_yet_valid"
        },
        not_before_unix_secs: Some(facts.not_before_unix_secs),
        not_after_unix_secs: Some(facts.not_after_unix_secs),
        renewal_due: valid && now >= due,
        pending: has_pending,
    })
}

pub(crate) fn online_expectation(
    directory: &Path,
    profile_sha256: &str,
    now: u64,
) -> Result<OnlineExpectation> {
    let store = Store::open(directory, false)?;
    expectation_from_store(&store, profile_sha256, now)
}

fn expectation_from_store(
    store: &Store,
    profile_sha256: &str,
    now: u64,
) -> Result<OnlineExpectation> {
    #[cfg(unix)]
    return aegis_client::protected_online_expectation::ProtectedOnlineExpectation::from_held(
        &store.protected,
        profile_sha256,
    )?
    .expectation_at(now);
    #[cfg(windows)]
    {
        profile(store, profile_sha256)?;
        ensure_idle(store)?;
        let record = store.record()?;
        ensure!(
            record.phase == "ready",
            "policy acknowledgement requires a completed identity"
        );
        validate_prepared(store, &record)?;
        let current = facts(store, &record, &store.read("device.pem")?)?;
        ensure!(
            record.certificate_sha256.as_ref() == Some(&current.fingerprint)
                && now >= current.not_before_unix_secs
                && now < current.not_after_unix_secs,
            "policy acknowledgement requires the current valid certificate and local key"
        );
        let (issued_generation, snapshot_sha256) =
            if let Some(saved) = optional::<SavedResponse>(store, COMPLETED)? {
                validate_response(store, &record, &saved, now, false)?;
                ensure!(
                    saved.receipt.certificate_sha256 == current.fingerprint,
                    "issuance receipt belongs to a different certificate"
                );
                (
                    Some(saved.receipt.issued_generation),
                    Some(saved.receipt.snapshot_sha256),
                )
            } else {
                (None, None)
            };
        Ok(OnlineExpectation {
            certificate_sha256: current.fingerprint,
            not_after_unix_secs: current.not_after_unix_secs,
            issued_generation,
            snapshot_sha256,
        })
    }
}

/// Public facts only. Local enrollment readiness does not attest live relay
/// policy adoption, installed traffic, capture or release acceptance.
#[derive(serde::Serialize)]
pub(crate) struct BundleReadyStatus {
    pub schema: &'static str,
    pub device_id: String,
    pub profile_sha256: String,
    pub device_ca_sha256: String,
    pub certificate_sha256: String,
    pub not_before_unix_secs: u64,
    pub not_after_unix_secs: u64,
    pub checked_at_unix_secs: u64,
    pub local_only: bool,
}

pub(crate) fn bundle_ready(
    directory: &Path,
    device_id: &str,
    profile_sha256: &str,
    device_ca_sha256: &str,
    now: u64,
) -> Result<BundleReadyStatus> {
    // One existing lock covers every identity check. No saved-response repair,
    // invitation, profile pinning, key generation or network operation exists.
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    ensure!(
        record.device_id == device_id,
        "unexpected enrolled device identity"
    );
    ensure!(
        sha(&pinned_ca(&store, &record)?) == device_ca_sha256,
        "device issuer CA differs from public bundle"
    );
    let expected = expectation_from_store(&store, profile_sha256, now)?;
    let certificate = store.read("device.pem")?;
    let current = facts(&store, &record, &certificate)?;
    enrollment::validate_device_certificate(
        device_id,
        &certificate,
        &pinned_ca(&store, &record)?,
        &store.read("device.key")?,
        now,
    )?;
    ensure!(
        current.fingerprint == expected.certificate_sha256,
        "device certificate changed during readiness check"
    );
    let renewal_at = current.not_before_unix_secs
        + (current.not_after_unix_secs - current.not_before_unix_secs) * 2 / 3;
    ensure!(
        now < renewal_at,
        "device renewal is due before local admission"
    );
    Ok(BundleReadyStatus {
        schema: "aegis_device_bundle_ready_v1",
        device_id: record.device_id,
        profile_sha256: profile_sha256.to_owned(),
        device_ca_sha256: device_ca_sha256.to_owned(),
        certificate_sha256: expected.certificate_sha256,
        not_before_unix_secs: current.not_before_unix_secs,
        not_after_unix_secs: current.not_after_unix_secs,
        checked_at_unix_secs: now,
        local_only: true,
    })
}

pub(crate) fn enable_online(
    directory: &Path,
    migration: &crate::device_bundle::online::OnlineMigration,
) -> Result<()> {
    migrate_profile(directory, migration.old_digest(), migration.new_digest())
}
fn migrate_profile(directory: &Path, old: &str, new: &str) -> Result<()> {
    protocol::digest(old)?;
    protocol::digest(new)?;
    ensure!(old != new, "profile migration must change profile version");
    let store = Store::open(directory, false)?;
    let record = store.record()?;
    validate_prepared(&store, &record)?;
    ensure!(
        optional::<Pending>(&store, REQUEST)?.is_none()
            && optional::<SavedResponse>(&store, RESPONSE)?.is_none(),
        "finish pending enrollment before profile migration"
    );
    let pin = std::str::from_utf8(&store.read(PROFILE)?)?
        .trim()
        .to_owned();
    if let Some(pending) = optional::<Migration>(&store, MIGRATION)? {
        ensure!(
            pending.version == 1 && pending.old_sha256 == old && pending.new_sha256 == new,
            "different profile migration requires operator recovery"
        );
        ensure!(
            pin == old || pin == new,
            "profile changed outside pending migration"
        );
    } else {
        if pin == new {
            return Ok(());
        }
        ensure!(pin == old, "profile migration requires exact prior pin");
        save_large(
            &store,
            MIGRATION,
            &Migration {
                version: 1,
                old_sha256: old.into(),
                new_sha256: new.into(),
            },
            false,
        )?;
    }
    if pin == old {
        store.save(PROFILE, new.as_bytes(), true)?;
    }
    ensure!(
        std::str::from_utf8(&store.read(PROFILE)?)?.trim() == new,
        "profile migration did not persist"
    );
    remove(&store, MIGRATION)
}

#[cfg(all(test, unix))]
#[path = "device_identity_online_tests.rs"]
mod tests;
