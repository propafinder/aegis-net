//! Authority-only issuance transactions. The private journal precedes every
//! registry change. A replay returns the retained certificate byte for byte;
//! it never signs again, refreshes policy, or claims fleet distribution.
use aegis_core::secure_channel::{
    enrollment::{
        self,
        protocol::{self, ConnectionChallenge, Operation, ProofPurpose},
    },
    enrollment_wire::{EnrollmentReceipt, ExchangeRequest, ReceiptState},
    registry::{
        self, CancellationJournal, CancellationObservation, CancellationReadGuard, DeviceRegistry,
        EnrollmentCancellation, InvitationPurpose, RegistryTransaction,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_RECEIPTS: usize = 1024;
const MAX_TOTAL: u64 = 16 * 1024 * 1024;
const MAX_RECEIPT: u64 = protocol::MAX_FRAME_BYTES as u64;
const MAX_JOURNAL: u64 = registry::MAX_REGISTRY_BYTES + MAX_RECEIPT + 4096;
fn default_lifetime() -> u64 {
    86400
}
fn default_count() -> usize {
    MAX_RECEIPTS
}
fn default_total() -> u64 {
    MAX_TOTAL
}
fn default_grace() -> u64 {
    3600
}
fn rejected(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Startup construction only. Each attempt uses the normal verified shared
/// lock/floor/issuance-barrier read; no snapshot or generation is substituted.
fn load_registry_for_startup(
    path: &Path,
    budget: Duration,
    interval: Duration,
    max_attempts: usize,
) -> io::Result<DeviceRegistry> {
    let deadline = Instant::now() + budget;
    let expired = || {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "device registry startup read exceeded its deadline",
        )
    };
    for attempt in 0..max_attempts {
        if Instant::now() >= deadline {
            return Err(expired());
        }
        let error = match DeviceRegistry::load(path) {
            Ok(registry) => {
                if Instant::now() >= deadline {
                    return Err(expired());
                }
                return Ok(registry);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => error,
            Err(error) => return Err(error),
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || attempt + 1 == max_attempts {
            return Err(error);
        }
        std::thread::sleep(interval.min(remaining));
        if Instant::now() >= deadline {
            return Err(error);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::WouldBlock,
        "device registry startup read exhausted its attempt bound",
    ))
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerConfig {
    pub registry: PathBuf,
    pub ca_cert: PathBuf,
    pub ca_key: PathBuf,
    pub profile_sha256: String,
    /// Opt-in receipt namespace for a second issuer sharing the same registry.
    /// It must equal this issuer's authenticated profile digest. Omission keeps
    /// the original receipt path and its retained replay semantics unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_namespace: Option<String>,
    #[serde(default = "default_lifetime")]
    pub lifetime_secs: u64,
    #[serde(default = "default_count")]
    pub max_receipts: usize,
    #[serde(default = "default_total")]
    pub max_receipt_bytes_total: u64,
    #[serde(default = "default_grace")]
    pub receipt_grace_secs: u64,
}

// Explicit null is a fact; omitted nullable fields are not silently defaulted.
fn required_nullable<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<T>, D::Error> {
    Option::<T>::deserialize(deserializer)
}

fn version_one<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let version = u8::deserialize(deserializer)?;
    if version != 1 {
        return Err(serde::de::Error::custom(
            "unsupported cancellation protocol version",
        ));
    }
    Ok(version)
}
fn selection_schema<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let schema = String::deserialize(deserializer)?;
    if schema != SELECTION_DOMAIN {
        return Err(serde::de::Error::custom(
            "cancellation selection schema invalid",
        ));
    }
    Ok(schema)
}
fn outcome_schema<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let schema = String::deserialize(deserializer)?;
    if schema != "aegis.enrollment-cancellation-outcome.v1" {
        return Err(serde::de::Error::custom(
            "cancellation outcome schema invalid",
        ));
    }
    Ok(schema)
}

const MAX_CANCELLATION_PROTOCOL: u64 = 16 * 1024;
const SELECTION_DOMAIN: &str = "aegis.enrollment-cancellation-selection.v1";

/// Exact current private authority facts; no certificate, key or invitation token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationTarget {
    pub registry: PathBuf,
    pub authority_config_sha256: String,
    pub issuer_config_sha256: String,
    pub public_ca_sha256: String,
    pub profile_sha256: String,
    pub device_id: String,
    #[serde(deserialize_with = "required_nullable")]
    pub expected_published_certificate_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub authenticated_cancelled_certificate_sha256: Option<String>,
    pub snapshot_generation: u64,
    pub snapshot_sha256: String,
    pub snapshot_file_sha256: String,
    pub floor_generation: u64,
    pub floor_snapshot_sha256: String,
    pub floor_file_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub pending_file_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub issuance_journal_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub issuance_request_id: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub issuance_receipt_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub cancellation_intent_sha256: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationSelection {
    #[serde(deserialize_with = "selection_schema")]
    pub schema: String,
    #[serde(deserialize_with = "version_one")]
    pub version: u8,
    pub target: CancellationTarget,
    pub selection_sha256: String,
}

/// Durable local transaction result, issued only after final verification under
/// the same exclusive lock. Publication and four live process ACKs are separate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancellationOutcome {
    #[serde(deserialize_with = "outcome_schema")]
    pub schema: String,
    #[serde(deserialize_with = "version_one")]
    pub version: u8,
    pub device_id: String,
    pub selection_sha256: String,
    #[serde(deserialize_with = "required_nullable")]
    pub expected_published_certificate_sha256: Option<String>,
    #[serde(deserialize_with = "required_nullable")]
    pub authenticated_cancelled_certificate_sha256: Option<String>,
    pub registry_generation: u64,
    pub canonical_public_policy_sha256: String,
    pub cancellation_intent_sha256: String,
    pub distribution_confirmed: bool,
    pub live_relay_acknowledgements_confirmed: bool,
    pub installed_acceptance: bool,
    pub readiness_authorization: bool,
}

pub struct Issuer {
    config: IssuerConfig,
    receipts: PathBuf,
    recovery_only: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredReceipt {
    version: u8,
    receipt: EnrollmentReceipt,
    public_key: String,
    // Initial invitation SHA256 only. Never its plaintext or a private key.
    invitation_sha256: Option<String>,
    retain_until_unix_secs: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    version: u8,
    predecessor_generation: u64,
    predecessor_sha256: String,
    successor: DeviceRegistry,
    stored: StoredReceipt,
}

impl Issuer {
    /// Read-only startup/check. Incomplete issuance is intentionally allowed
    /// here: authenticated exact recovery must remain available after restart.
    pub fn open(config: &IssuerConfig) -> io::Result<Self> {
        Self::open_mode(config, false, false)
    }

    /// Read-only construction for the explicit local recovery command. It
    /// verifies the pinned public CA and historical signed journal, needs no
    /// signing key, and cannot be used to serve new exchanges.
    pub fn open_recovery(config: &IssuerConfig) -> io::Result<Self> {
        Self::open_mode(config, true, false)
    }

    /// Exact-ID cancellation may precede issuance or recover its own paired
    /// publication. It still cannot sign or process network exchanges.
    pub fn open_cancellation(config: &IssuerConfig) -> io::Result<Self> {
        Self::open_mode(config, true, true)
    }

    fn open_mode(
        config: &IssuerConfig,
        recovery_only: bool,
        cancellation: bool,
    ) -> io::Result<Self> {
        protocol::digest(&config.profile_sha256)?;
        if config
            .receipt_namespace
            .as_deref()
            .is_some_and(|namespace| namespace != config.profile_sha256.as_str())
        {
            return Err(rejected(
                "issuer receipt namespace must equal its profile digest",
            ));
        }
        if !(60..=30 * 86400).contains(&config.lifetime_secs)
            || !(1..=MAX_RECEIPTS).contains(&config.max_receipts)
            || !(MAX_RECEIPT..=MAX_TOTAL).contains(&config.max_receipt_bytes_total)
            || config.receipt_grace_secs > 86400
        {
            return Err(rejected("issuer limits invalid"));
        }
        for path in [&config.registry, &config.ca_cert, &config.ca_key] {
            if !path.is_absolute() {
                return Err(rejected("issuer paths must be absolute"));
            }
            if !recovery_only || path != &config.ca_key {
                enrollment::trusted_parent(path)?;
            }
        }
        let ca = read_public(&config.ca_cert)?;
        enrollment::validate_device_ca(&ca)?;
        // Descriptor validation includes single link; key material stays in
        // secret_file's zeroizing allocation and is not retained by Issuer.
        if !recovery_only {
            validate_private(&config.ca_key, 64 * 1024)?;
            let key = aegis_core::secret_file::read(&config.ca_key, 64 * 1024)?;
            enrollment::validate_issuer_key(&ca, &key, registry::unix_now()?)?;
        }
        let mut receipts = config.registry.as_os_str().to_os_string();
        receipts.push(".issuance-receipts");
        if let Some(namespace) = &config.receipt_namespace {
            receipts.push("-");
            receipts.push(namespace);
        }
        let issuer = Self {
            config: config.clone(),
            receipts: receipts.into(),
            recovery_only,
        };
        if issuer.receipts.try_exists()? {
            check_directory(&issuer.receipts)?;
        }
        if let Some(pending) = issuer.pending()? {
            issuer.validate_pending(&pending)?;
        } else {
            if recovery_only && !cancellation {
                return Err(rejected("no pending issuance"));
            }
            if !cancellation {
                load_registry_for_startup(
                    &config.registry,
                    Duration::from_secs(5),
                    Duration::from_millis(50),
                    101,
                )?;
            }
        }
        Ok(issuer)
    }

    pub fn exchange(
        &self,
        request: &ExchangeRequest,
        challenge: &mut ConnectionChallenge,
    ) -> io::Result<EnrollmentReceipt> {
        self.exchange_with_clock(request, challenge, registry::unix_now)
    }

    fn exchange_with_clock(
        &self,
        request: &ExchangeRequest,
        challenge: &mut ConnectionChallenge,
        clock: impl Fn() -> io::Result<u64>,
    ) -> io::Result<EnrollmentReceipt> {
        if self.recovery_only {
            return Err(rejected(
                "recovery-only issuer cannot process network exchanges",
            ));
        }
        request.validate()?;
        if request.binding.profile_sha256 != self.config.profile_sha256 {
            return Err(rejected("issuer profile binding rejected"));
        }
        let key = protocol::csr_public_key(&request.csr_pem)?;
        let transaction = RegistryTransaction::begin_issuance(&self.config.registry)?;
        let now = clock()?;
        let proof = challenge.verify(
            &request.binding,
            request.purpose,
            &key,
            &request.proof_signature()?,
            now,
        )?;
        if let Some(pending) = self.pending()? {
            self.validate_pending(&pending)?;
            self.match_request(&pending.stored, request, &key)?;
            proof.check(&request.binding, &key, now, false)?;
            self.finish(&transaction, &pending)?;
            return self.replay(&transaction, &pending.stored, now);
        }
        if let Some(stored) = self.receipt(&request.binding.request_id)? {
            self.validate_stored(&stored)?;
            self.match_request(&stored, request, &key)?;
            proof.check(&request.binding, &key, now, false)?;
            return self.replay(&transaction, &stored, now);
        }
        proof.check(&request.binding, &key, now, true)?;
        let mut successor = transaction.load()?;
        current_policy(&successor, now)?;
        let predecessor_generation = successor.generation;
        let predecessor_sha256 = hex::encode(registry::registry_digest(&successor)?);
        let (device_id, invitation_hash) = match request.binding.operation {
            Operation::Redeem => {
                let token = request
                    .invitation
                    .as_deref()
                    .ok_or_else(|| rejected("invitation required"))?;
                let hash = hex::encode(Sha256::digest(token.as_bytes()));
                let invitation = successor
                    .invitations
                    .iter_mut()
                    .find(|i| i.token_sha256 == hash)
                    .ok_or_else(|| rejected("invitation rejected"))?;
                if invitation.consumed
                    || invitation.expires_unix_secs <= now
                    || !matches!(invitation.purpose, InvitationPurpose::Enroll)
                    || successor
                        .devices
                        .iter()
                        .any(|d| d.device_id == invitation.device_id)
                {
                    return Err(rejected("invitation rejected"));
                }
                invitation.consumed = true;
                (invitation.device_id.clone(), Some(hash))
            }
            Operation::Renew => {
                let predecessor = request
                    .binding
                    .predecessor_sha256
                    .as_deref()
                    .ok_or_else(|| rejected("predecessor required"))?;
                let device = successor
                    .devices
                    .iter()
                    .find(|d| {
                        d.certificate_sha256 == predecessor
                            && !d.revoked
                            && d.not_after_unix_secs > now
                    })
                    .ok_or_else(|| rejected("renewal predecessor rejected"))?;
                let ca = read_public(&self.config.ca_cert)?;
                let cert = request
                    .predecessor_certificate_pem
                    .as_deref()
                    .ok_or_else(|| rejected("predecessor certificate required"))?;
                let facts = enrollment::validate_device_certificate_public(
                    &device.device_id,
                    cert.as_bytes(),
                    &ca,
                    now,
                )?;
                let due = facts.not_before_unix_secs
                    + (facts.not_after_unix_secs - facts.not_before_unix_secs) * 2 / 3;
                if facts.fingerprint != predecessor || facts.public_key != key || now < due {
                    return Err(rejected(
                        "renewal is not due or does not prove the current key",
                    ));
                }
                (device.device_id.clone(), None)
            }
        };
        if transaction.enrollment_cancellation(&device_id)?.is_some() {
            return Err(rejected("device enrollment is permanently cancelled"));
        }
        // Only an authorized issuance may clean expired receipts or create the
        // private receipt directory. Count/bytes are streamed under writer lock.
        self.prepare_quota(now)?;
        let ca = read_public(&self.config.ca_cert)?;
        validate_private(&self.config.ca_key, 64 * 1024)?;
        let ca_key = aegis_core::secret_file::read(&self.config.ca_key, 64 * 1024)?;
        let issued = enrollment::sign_csr(
            &device_id,
            &request.csr_pem,
            utf8(&ca)?,
            utf8(&ca_key)?,
            now,
            self.config.lifetime_secs,
        )?;
        if let Some(device) = successor
            .devices
            .iter_mut()
            .find(|d| d.device_id == device_id)
        {
            *device = issued.record.clone();
        } else {
            successor.devices.push(issued.record.clone());
        }
        successor.generation = successor
            .generation
            .checked_add(1)
            .ok_or_else(|| rejected("registry generation exhausted"))?;
        successor.validate()?;
        let stored = StoredReceipt {
            version: 1,
            receipt: EnrollmentReceipt {
                version: 1,
                binding: request.binding.clone(),
                device_id,
                certificate_pem: issued.certificate_pem,
                certificate_sha256: issued.record.certificate_sha256,
                not_before_unix_secs: now,
                not_after_unix_secs: issued.record.not_after_unix_secs,
                issued_generation: successor.generation,
                snapshot_sha256: hex::encode(registry::registry_digest(&successor)?),
                state: ReceiptState::IssuedPendingDistribution,
            },
            public_key: hex::encode(key),
            invitation_sha256: invitation_hash,
            retain_until_unix_secs: issued
                .record
                .not_after_unix_secs
                .checked_add(self.config.receipt_grace_secs)
                .ok_or_else(|| rejected("receipt retention overflow"))?,
        };
        self.validate_stored(&stored)?;
        let pending = Pending {
            version: 1,
            predecessor_generation,
            predecessor_sha256,
            successor,
            stored,
        };
        self.validate_pending(&pending)?;
        // Recheck the one-connection proof immediately before the first durable
        // signing outcome. A slow key/CA read cannot extend its authorization.
        proof.check(&request.binding, &key, clock()?, true)?;
        write_new(
            &registry::issuance_pending_path(&self.config.registry),
            &serialize(&pending, MAX_JOURNAL)?,
        )?;
        self.finish(&transaction, &pending)?;
        self.replay(&transaction, &pending.stored, now)
    }

    /// Explicit local operator recovery only; never invoked for an unrelated
    /// network request. Finishes exact retained work even after leaf expiry so
    /// expired work cannot strand the global mutation barrier forever.
    pub fn recover_pending(&self) -> io::Result<()> {
        let transaction = RegistryTransaction::begin_issuance(&self.config.registry)?;
        let pending = self
            .pending()?
            .ok_or_else(|| rejected("no pending issuance"))?;
        self.validate_pending(&pending)?;
        self.finish(&transaction, &pending)
    }

    /// Explicit exact-ID operator cancellation, without signing. Any published
    /// record requires the caller's exact certificate CAS. The private intent
    /// precedes recovery so a crash cannot turn late journal work into readable
    /// active authorization. An unrelated pending request is never completed.
    pub fn cancel_enrollment(
        &self,
        device_id: &str,
        expected_certificate_sha256: Option<&str>,
    ) -> io::Result<()> {
        self.cancel_enrollment_with(device_id, expected_certificate_sha256, || Ok(()))
    }

    // Private deterministic publication-boundary observer. Production supplies
    // only the no-op above; there is no CLI/runtime fault-injection interface.
    fn cancel_enrollment_with(
        &self,
        device_id: &str,
        expected_certificate_sha256: Option<&str>,
        observer: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        if !self.recovery_only {
            return Err(rejected("cancellation requires recovery-only issuer"));
        }
        registry::validate_device_id(device_id)?;
        if let Some(expected) = expected_certificate_sha256 {
            protocol::digest(expected)?;
        }
        let transaction = RegistryTransaction::begin_issuance(&self.config.registry)?;
        self.cancel_in_transaction(
            &transaction,
            device_id,
            expected_certificate_sha256,
            observer,
        )?;
        Ok(())
    }

    fn cancel_in_transaction(
        &self,
        transaction: &RegistryTransaction,
        device_id: &str,
        expected_certificate_sha256: Option<&str>,
        observer: impl FnMut() -> io::Result<()>,
    ) -> io::Result<EnrollmentCancellation> {
        let pending = self.pending()?;
        if let Some(pending) = &pending {
            self.validate_pending(pending)?;
            if pending.stored.receipt.device_id != device_id {
                return Err(rejected("unrelated pending issuance blocks cancellation"));
            }
        }
        let intent = if let Some(intent) = transaction.enrollment_cancellation(device_id)? {
            if intent.expected_certificate_sha256.as_deref() != expected_certificate_sha256 {
                return Err(rejected("cancellation replay expectation changed"));
            }
            intent
        } else {
            let current = match &pending {
                Some(pending) => transaction.load_cancellation_snapshot(
                    pending.predecessor_generation,
                    &pending.predecessor_sha256,
                    &pending.successor,
                )?,
                None => transaction.load()?,
            };
            let published = current
                .devices
                .iter()
                .find(|row| row.device_id == device_id);
            if published.map(|row| row.certificate_sha256.as_str()) != expected_certificate_sha256 {
                return Err(rejected(
                    "published cancellation target requires exact certificate expectation",
                ));
            }
            let target = pending
                .as_ref()
                .map(|journal| journal.stored.receipt.certificate_sha256.as_str())
                .or_else(|| published.map(|row| row.certificate_sha256.as_str()));
            transaction.record_enrollment_cancellation(
                device_id,
                expected_certificate_sha256,
                target,
                &current,
            )?;
            transaction
                .enrollment_cancellation(device_id)?
                .ok_or_else(|| rejected("durable cancellation intent missing"))?
        };
        if let Some(pending) = &pending {
            self.finish_with(transaction, pending, observer)?;
        }
        transaction.complete_enrollment_cancellation(device_id)?;
        if cancelled_snapshot(&transaction.load()?, &intent)?.is_some() {
            return Err(rejected("cancelled publication did not persist"));
        }
        Ok(intent)
    }

    /// Inspection never constructs a mutable transaction or reads the signing
    /// key. The existing lock must already exist; contention refuses immediately.
    pub fn inspect_cancellation(
        &self,
        device_id: &str,
        authority_config_sha256: &str,
    ) -> io::Result<CancellationSelection> {
        self.check_cancellation_protocol(device_id, authority_config_sha256)?;
        let guard = CancellationReadGuard::open(&self.config.registry)?;
        self.select_cancellation(device_id, authority_config_sha256, |journal| {
            guard.observe(device_id, journal)
        })
    }

    pub fn cancel_selected_enrollment(
        &self,
        device_id: &str,
        expected_certificate_sha256: Option<&str>,
        selection_sha256: &str,
        authority_config_sha256: &str,
    ) -> io::Result<CancellationOutcome> {
        self.cancel_selected_with(
            device_id,
            expected_certificate_sha256,
            selection_sha256,
            authority_config_sha256,
            || Ok(()),
        )
    }

    fn check_cancellation_protocol(&self, device_id: &str, context: &str) -> io::Result<()> {
        if !self.recovery_only {
            return Err(rejected("cancellation requires recovery-only issuer"));
        }
        registry::validate_device_id(device_id)?;
        protocol::digest(context)?;
        Ok(())
    }

    fn select_cancellation(
        &self,
        device_id: &str,
        authority_config_sha256: &str,
        observe: impl FnOnce(Option<&CancellationJournal<'_>>) -> io::Result<CancellationObservation>,
    ) -> io::Result<CancellationSelection> {
        // Parse and hash one bounded authenticated journal buffer while the
        // caller holds its read-only or exclusive registry lock.
        let journal_path = registry::issuance_pending_path(&self.config.registry);
        let retained = match read_file(&journal_path, MAX_JOURNAL, true) {
            Ok(bytes) => {
                let journal: Pending = serde_json::from_slice(&bytes)
                    .map_err(|_| rejected("issuance journal JSON invalid"))?;
                self.validate_pending(&journal)?;
                if journal.stored.receipt.device_id != device_id {
                    return Err(rejected("unrelated pending issuance blocks cancellation"));
                }
                Some((journal, hex::encode(Sha256::digest(bytes))))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e),
        };
        let descriptor = retained.as_ref().map(|(journal, _)| CancellationJournal {
            predecessor_generation: journal.predecessor_generation,
            predecessor_sha256: &journal.predecessor_sha256,
            successor: &journal.successor,
        });
        let facts = observe(descriptor.as_ref())?;
        let published = facts
            .snapshot
            .devices
            .iter()
            .find(|row| row.device_id == device_id);
        let (expected, cancelled) = if let Some(intent) = &facts.intent {
            if retained.as_ref().is_some_and(|(journal, _)| {
                intent.cancelled_certificate_sha256.as_deref()
                    != Some(journal.stored.receipt.certificate_sha256.as_str())
            }) {
                return Err(rejected(
                    "cancellation intent target conflicts with retained receipt",
                ));
            }
            (
                intent.expected_certificate_sha256.clone(),
                intent.cancelled_certificate_sha256.clone(),
            )
        } else {
            (
                published.map(|row| row.certificate_sha256.clone()),
                retained
                    .as_ref()
                    .map(|(journal, _)| journal.stored.receipt.certificate_sha256.clone())
                    .or_else(|| published.map(|row| row.certificate_sha256.clone())),
            )
        };
        let target = CancellationTarget {
            registry: enrollment::trusted_parent(&self.config.registry)?.join(
                self.config
                    .registry
                    .file_name()
                    .ok_or_else(|| rejected("registry needs a filename"))?,
            ),
            authority_config_sha256: authority_config_sha256.to_owned(),
            issuer_config_sha256: hex::encode(Sha256::digest(serialize(&self.config, 64 * 1024)?)),
            public_ca_sha256: hex::encode(Sha256::digest(read_file(
                &self.config.ca_cert,
                1024 * 1024,
                false,
            )?)),
            profile_sha256: self.config.profile_sha256.clone(),
            device_id: device_id.to_owned(),
            expected_published_certificate_sha256: expected,
            authenticated_cancelled_certificate_sha256: cancelled,
            snapshot_generation: facts.snapshot.generation,
            snapshot_sha256: hex::encode(registry::registry_digest(&facts.snapshot)?),
            snapshot_file_sha256: facts.snapshot_file_sha256,
            floor_generation: facts.floor_generation,
            floor_snapshot_sha256: facts.floor_snapshot_sha256,
            floor_file_sha256: facts.floor_file_sha256,
            pending_file_sha256: facts.pending_file_sha256,
            issuance_journal_sha256: retained.as_ref().map(|(_, sha)| sha.clone()),
            issuance_request_id: retained
                .as_ref()
                .map(|(journal, _)| journal.stored.receipt.binding.request_id.clone()),
            issuance_receipt_sha256: retained
                .as_ref()
                .map(|(journal, _)| {
                    serialize(&journal.stored.receipt, MAX_RECEIPT)
                        .map(|bytes| hex::encode(Sha256::digest(bytes)))
                })
                .transpose()?,
            cancellation_intent_sha256: facts.intent_sha256,
        };
        let selection_sha256 = hex::encode(Sha256::digest(serialize(
            &(SELECTION_DOMAIN, 1u8, &target),
            MAX_CANCELLATION_PROTOCOL,
        )?));
        let selection = CancellationSelection {
            schema: SELECTION_DOMAIN.to_owned(),
            version: 1,
            target,
            selection_sha256,
        };
        let _ = serialize(&selection, MAX_CANCELLATION_PROTOCOL)?;
        Ok(selection)
    }

    fn cancel_selected_with(
        &self,
        device_id: &str,
        expected_certificate_sha256: Option<&str>,
        selection_sha256: &str,
        authority_config_sha256: &str,
        observer: impl FnMut() -> io::Result<()>,
    ) -> io::Result<CancellationOutcome> {
        self.check_cancellation_protocol(device_id, authority_config_sha256)?;
        protocol::digest(selection_sha256)?;
        if let Some(expected) = expected_certificate_sha256 {
            protocol::digest(expected)?;
        }
        let transaction = RegistryTransaction::begin_issuance(&self.config.registry)?;
        let selected = self.select_cancellation(device_id, authority_config_sha256, |journal| {
            transaction.observe_enrollment_cancellation(device_id, journal)
        })?;
        // No intent or policy write has occurred. A stale selection fails once.
        if selected.selection_sha256 != selection_sha256
            || selected
                .target
                .expected_published_certificate_sha256
                .as_deref()
                != expected_certificate_sha256
        {
            return Err(rejected(
                "cancellation selection or published expectation changed",
            ));
        }
        let intent = self.cancel_in_transaction(
            &transaction,
            device_id,
            expected_certificate_sha256,
            observer,
        )?;
        if intent.cancelled_certificate_sha256
            != selected.target.authenticated_cancelled_certificate_sha256
        {
            return Err(rejected("cancelled target changed during transaction"));
        }
        let current = transaction.load()?;
        if cancelled_snapshot(&current, &intent)?.is_some() {
            return Err(rejected("cancelled publication did not persist"));
        }
        let verified = transaction.observe_enrollment_cancellation(device_id, None)?;
        let outcome = CancellationOutcome {
            schema: "aegis.enrollment-cancellation-outcome.v1".to_owned(),
            version: 1,
            device_id: device_id.to_owned(),
            selection_sha256: selected.selection_sha256,
            expected_published_certificate_sha256: intent.expected_certificate_sha256,
            authenticated_cancelled_certificate_sha256: intent.cancelled_certificate_sha256,
            registry_generation: current.generation,
            canonical_public_policy_sha256: hex::encode(Sha256::digest(
                crate::device_policy::canonical(&current)
                    .map_err(|_| rejected("canonical cancelled policy invalid"))?,
            )),
            cancellation_intent_sha256: verified
                .intent_sha256
                .ok_or_else(|| rejected("durable cancellation intent missing"))?,
            distribution_confirmed: false,
            live_relay_acknowledgements_confirmed: false,
            installed_acceptance: false,
            readiness_authorization: false,
        };
        let _ = serialize(&outcome, MAX_CANCELLATION_PROTOCOL)?;
        Ok(outcome)
    }

    fn match_request(
        &self,
        stored: &StoredReceipt,
        request: &ExchangeRequest,
        key: &[u8; 32],
    ) -> io::Result<()> {
        if stored.receipt.binding != request.binding || stored.public_key != hex::encode(key) {
            return Err(rejected("request conflicts with retained issuance"));
        }
        if request.purpose == ProofPurpose::Authorize
            && request.binding.operation == Operation::Redeem
            && request
                .invitation
                .as_ref()
                .map(|token| hex::encode(Sha256::digest(token.as_bytes())))
                != stored.invitation_sha256
        {
            return Err(rejected("invitation conflicts with retained issuance"));
        }
        Ok(())
    }
    fn replay(
        &self,
        transaction: &RegistryTransaction,
        stored: &StoredReceipt,
        now: u64,
    ) -> io::Result<EnrollmentReceipt> {
        let current = transaction.load()?;
        if transaction
            .enrollment_cancellation(&stored.receipt.device_id)?
            .is_some()
            || stored.receipt.not_after_unix_secs <= now
            || !current.devices.iter().any(|d| {
                d.device_id == stored.receipt.device_id
                    && !d.revoked
                    && d.certificate_sha256 == stored.receipt.certificate_sha256
            })
        {
            return Err(rejected(
                "retained certificate expired, revoked or superseded",
            ));
        }
        Ok(stored.receipt.clone())
    }
    fn pending(&self) -> io::Result<Option<Pending>> {
        read_json_optional(
            &registry::issuance_pending_path(&self.config.registry),
            MAX_JOURNAL,
        )
    }
    fn receipt(&self, id: &str) -> io::Result<Option<StoredReceipt>> {
        protocol::digest(id)?;
        if !self.receipts.try_exists()? {
            return Ok(None);
        }
        check_directory(&self.receipts)?;
        read_json_optional(&self.receipts.join(format!("{id}.json")), MAX_RECEIPT)
    }
    fn validate_stored(&self, stored: &StoredReceipt) -> io::Result<()> {
        stored.receipt.validate()?;
        let receipt = &stored.receipt;
        if stored.version != 1
            || receipt.binding.profile_sha256 != self.config.profile_sha256
            || stored.retain_until_unix_secs < receipt.not_after_unix_secs
            || stored.retain_until_unix_secs > receipt.not_after_unix_secs.saturating_add(86400)
            || (receipt.binding.operation == Operation::Redeem)
                != stored.invitation_sha256.is_some()
        {
            return Err(rejected("retained receipt policy invalid"));
        }
        if let Some(hash) = &stored.invitation_sha256 {
            protocol::digest(hash)?;
        }
        let ca = read_public(&self.config.ca_cert)?;
        let facts = enrollment::device_certificate_metadata(
            &receipt.device_id,
            receipt.certificate_pem.as_bytes(),
            &ca,
        )?;
        if facts.fingerprint != receipt.certificate_sha256
            || facts.public_key != protocol::digest(&stored.public_key)?
            || facts.not_before_unix_secs != receipt.not_before_unix_secs
            || facts.not_after_unix_secs != receipt.not_after_unix_secs
        {
            return Err(rejected("retained certificate does not match receipt"));
        }
        serialize(stored, MAX_RECEIPT)?;
        Ok(())
    }
    fn validate_pending(&self, pending: &Pending) -> io::Result<()> {
        self.validate_stored(&pending.stored)?;
        let receipt = &pending.stored.receipt;
        protocol::digest(&pending.predecessor_sha256)?;
        if pending.version != 1
            || pending.predecessor_generation == 0
            || pending.predecessor_generation.checked_add(1) != Some(pending.successor.generation)
            || receipt.issued_generation != pending.successor.generation
            || hex::encode(registry::registry_digest(&pending.successor)?)
                != receipt.snapshot_sha256
            || !pending.successor.devices.iter().any(|d| {
                d.device_id == receipt.device_id
                    && !d.revoked
                    && d.certificate_sha256 == receipt.certificate_sha256
                    && d.not_after_unix_secs == receipt.not_after_unix_secs
            })
        {
            return Err(rejected("pending issuance snapshot invalid"));
        }
        Ok(())
    }
    fn finish(&self, transaction: &RegistryTransaction, pending: &Pending) -> io::Result<()> {
        self.finish_with(transaction, pending, || Ok(()))
    }

    fn finish_with(
        &self,
        transaction: &RegistryTransaction,
        pending: &Pending,
        mut observer: impl FnMut() -> io::Result<()>,
    ) -> io::Result<()> {
        let cancellation =
            transaction.enrollment_cancellation(&pending.stored.receipt.device_id)?;
        if let Some(intent) = &cancellation {
            if intent.cancelled_certificate_sha256.as_deref()
                != Some(pending.stored.receipt.certificate_sha256.as_str())
                || !((intent.predecessor_generation == pending.predecessor_generation
                    && intent.predecessor_sha256 == pending.predecessor_sha256)
                    || (intent.predecessor_generation == pending.successor.generation
                        && intent.predecessor_sha256 == pending.stored.receipt.snapshot_sha256))
            {
                return Err(rejected(
                    "cancellation intent conflicts with pending issuance",
                ));
            }
        }
        let cancelled = cancellation
            .as_ref()
            .map(|intent| {
                cancelled_snapshot(&pending.successor, intent)?
                    .ok_or_else(|| rejected("pending cancellation successor missing"))
            })
            .transpose()?;
        if let Ok(current) = transaction.load_published_issuance() {
            let digest = hex::encode(registry::registry_digest(&current)?);
            if !((current.generation == pending.predecessor_generation
                && digest == pending.predecessor_sha256)
                || (current.generation == pending.successor.generation
                    && digest == pending.stored.receipt.snapshot_sha256)
                || cancelled.as_ref().is_some_and(|value| {
                    current.generation == value.generation
                        && registry::registry_digest(value)
                            .is_ok_and(|expected| digest == hex::encode(expected))
                }))
            {
                return Err(rejected(
                    "published registry conflicts with pending issuance",
                ));
            }
        }
        // A missing original floor is never initial enrollment: this journal
        // explicitly records an already-published predecessor. Do not let the
        // generic first-publication case recreate both lost authority files.
        let _ = read_file(&registry::floor_path(&self.config.registry), 4096, false)?;
        // A mismatched floor/snapshot pair is repaired only by core's existing
        // exact pending/floor checks. No reset, delete-floor or fallback path.
        // A crash during cancellation may already have advanced the floor to
        // the revoked successor. Recover exactly that retained derivation;
        // never roll back to the original active issuance floor.
        if let Some(cancelled) = &cancelled {
            let cancelled_pending = transaction.issuance_pending_matches(cancelled)?;
            if cancelled_pending {
                transaction.observe_enrollment_cancellation(
                    &pending.stored.receipt.device_id,
                    Some(&CancellationJournal {
                        predecessor_generation: pending.predecessor_generation,
                        predecessor_sha256: &pending.predecessor_sha256,
                        successor: &pending.successor,
                    }),
                )?;
            }
            if !transaction.issuance_floor_matches(cancelled)? && !cancelled_pending {
                transaction.apply_issuance_snapshot(&pending.successor)?;
                observer()?;
            }
            transaction.apply_issuance_snapshot(cancelled)?;
            observer()?;
        } else {
            transaction.apply_issuance_snapshot(&pending.successor)?;
            observer()?;
        }
        ensure_directory(&self.receipts)?;
        let path = self.receipts.join(format!(
            "{}.json",
            pending.stored.receipt.binding.request_id
        ));
        let bytes = serialize(&pending.stored, MAX_RECEIPT)?;
        if let Some(existing) = self.receipt(&pending.stored.receipt.binding.request_id)? {
            if serialize(&existing, MAX_RECEIPT)? != bytes {
                return Err(rejected(
                    "committed receipt conflicts with pending issuance",
                ));
            }
        } else {
            write_new(&path, &bytes)?;
        }
        let current = transaction.load_published_issuance()?;
        let expected = cancelled.as_ref().unwrap_or(&pending.successor);
        if hex::encode(registry::registry_digest(&current)?)
            != hex::encode(registry::registry_digest(expected)?)
        {
            return Err(rejected("issued snapshot publication did not persist"));
        }
        // Ensure the retained response and both directory entries are durable
        // before removing the barrier visible to every ordinary writer/reader.
        File::open(&path)?.sync_all()?;
        File::open(&self.receipts)?.sync_all()?;
        observer()?;
        fs::remove_file(registry::issuance_pending_path(&self.config.registry))?;
        File::open(enrollment::trusted_parent(&self.config.registry)?)?.sync_all()
    }
    fn prepare_quota(&self, now: u64) -> io::Result<()> {
        ensure_directory(&self.receipts)?;
        let mut count = 0usize;
        let mut total = 0u64;
        let mut examined = 0usize;
        for entry in fs::read_dir(&self.receipts)? {
            let entry = entry?;
            examined += 1;
            if examined > MAX_RECEIPTS {
                return Err(rejected("issuance receipt directory exceeds count bound"));
            }
            let name = entry.file_name();
            let id = name
                .to_str()
                .and_then(|name| name.strip_suffix(".json"))
                .ok_or_else(|| rejected("receipt filename invalid"))?;
            protocol::digest(id)?;
            let stored: StoredReceipt = read_json_optional(&entry.path(), MAX_RECEIPT)?
                .ok_or_else(|| rejected("receipt disappeared"))?;
            self.validate_stored(&stored)?;
            if stored.receipt.binding.request_id != id {
                return Err(rejected("receipt filename binding invalid"));
            }
            if stored.retain_until_unix_secs < now {
                fs::remove_file(entry.path())?;
            } else {
                count += 1;
                total = total
                    .checked_add(serialize(&stored, MAX_RECEIPT)?.len() as u64)
                    .ok_or_else(|| rejected("receipt quota overflow"))?;
            }
        }
        File::open(&self.receipts)?.sync_all()?;
        if count >= self.config.max_receipts
            || total.saturating_add(MAX_RECEIPT) > self.config.max_receipt_bytes_total
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "issuance receipt quota exhausted",
            ));
        }
        Ok(())
    }
}

/// Changes only this intent's ID/invitations and generation. Validity and every
/// other identity remain byte-for-byte data. No policy refresh or floor bypass.
fn cancelled_snapshot(
    current: &DeviceRegistry,
    intent: &EnrollmentCancellation,
) -> io::Result<Option<DeviceRegistry>> {
    intent.cancelled_snapshot(current)
}

fn current_policy(registry: &DeviceRegistry, now: u64) -> io::Result<()> {
    registry.validate()?;
    let validity = registry
        .validity
        .ok_or_else(|| rejected("online issuance requires v2 policy"))?;
    if registry.version != 2
        || validity.issued_at_unix_secs > now
        || validity.expires_at_unix_secs <= now
    {
        return Err(rejected(
            "online issuance requires current authority policy",
        ));
    }
    Ok(())
}
fn utf8(bytes: &[u8]) -> io::Result<&str> {
    std::str::from_utf8(bytes).map_err(|_| rejected("enrollment input encoding invalid"))
}
fn serialize(value: &impl Serialize, limit: u64) -> io::Result<Vec<u8>> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| rejected("issuance journal encoding invalid"))?;
    if bytes.len() as u64 > limit {
        return Err(rejected("issuance journal exceeds bound"));
    }
    Ok(bytes)
}
fn check_directory(path: &Path) -> io::Result<()> {
    enrollment::trusted_parent(&path.join("entry"))?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() {
        return Err(rejected("receipt directory must not be a symlink"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(rejected("receipt directory must be owner-private"));
        }
    }
    Ok(())
}
fn ensure_directory(path: &Path) -> io::Result<()> {
    enrollment::trusted_parent(path)?;
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let mut builder = builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => File::open(enrollment::trusted_parent(path)?)?.sync_all()?,
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => (),
        Err(e) => return Err(e),
    }
    check_directory(path)
}
fn validate_private(path: &Path, limit: u64) -> io::Result<()> {
    open_file(path, limit, true).map(|_| ())
}
fn read_public(path: &Path) -> io::Result<Vec<u8>> {
    read_file(path, 64 * 1024, false)
}
fn open_file(path: &Path, limit: u64, private: bool) -> io::Result<File> {
    #[cfg(not(unix))]
    let _ = private;
    enrollment::trusted_parent(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(rejected("issuance input must be a bounded regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & if private { 0o077 } else { 0o022 } != 0
            || metadata.nlink() != 1
        {
            return Err(rejected("issuance input owner, mode or link count invalid"));
        }
    }
    Ok(file)
}
fn read_file(path: &Path, limit: u64, private: bool) -> io::Result<Vec<u8>> {
    let file = open_file(path, limit, private)?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(rejected("issuance input exceeds bound"));
    }
    Ok(bytes)
}
fn read_json_optional<T: serde::de::DeserializeOwned>(
    path: &Path,
    limit: u64,
) -> io::Result<Option<T>> {
    match read_file(path, limit, true) {
        Ok(bytes) => Ok(Some(
            serde_json::from_slice(&bytes)
                .map_err(|_| rejected("issuance journal JSON invalid"))?,
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}
fn write_new(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = enrollment::trusted_parent(path)?;
    let mut temporary = tempfile::NamedTempFile::new_in(&parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()
}

#[cfg(all(test, unix))]
#[path = "enrollment_store_tests.rs"]
mod tests;
