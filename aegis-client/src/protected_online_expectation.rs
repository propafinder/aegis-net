//! Existing online issuance validator over one retained Unix Store lock.
//! File custody and certificate/receipt checks are local only; this is not a
//! relay policy ACK, renewal permit, packet lease or provider factory.

use crate::{
    online_expectation::OnlineExpectation, protected_identity_store::ProtectedIdentityStore,
};
use aegis_core::secure_channel::{
    enrollment::{self, protocol::Operation},
    enrollment_wire::EnrollmentReceipt,
    registry,
};
use anyhow::{ensure, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{io, path::Path};
use zeroize::Zeroizing;

const REQUEST: &str = "online-request.json";
const RESPONSE: &str = "online-response.json";
const COMPLETED: &str = "online-completed.json";
const MIGRATION: &str = "online-profile-migration.json";
const PROFILE: &str = "bundle-profile.sha256";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u8,
    device_id: String,
    phase: String,
    device_ca_sha256: String,
    certificate_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedResponse {
    version: u8,
    receipt: EnrollmentReceipt,
    predecessor_certificate_pem: Option<String>,
}
enum HeldStore<'a> {
    Owned(ProtectedIdentityStore),
    Borrowed(&'a ProtectedIdentityStore),
}
impl HeldStore<'_> {
    fn store(&self) -> &ProtectedIdentityStore {
        match self {
            Self::Owned(store) => store,
            Self::Borrowed(store) => store,
        }
    }
}

pub struct ProtectedOnlineExpectation<'a> {
    store: HeldStore<'a>,
    profile_sha256: String,
}
impl ProtectedOnlineExpectation<'static> {
    /// Opens an existing protected identity exactly once and retains its lock
    /// through every subsequent observation, including a caller's awaited ACK.
    pub fn open_existing(directory: &Path, profile_sha256: &str) -> Result<Self> {
        aegis_core::secure_channel::enrollment::protocol::digest(profile_sha256)?;
        Ok(Self {
            store: HeldStore::Owned(ProtectedIdentityStore::open_existing(directory)?),
            profile_sha256: profile_sha256.to_owned(),
        })
    }
}
impl<'a> ProtectedOnlineExpectation<'a> {
    /// Reuse a Store lock that the binary already owns; never open a second
    /// descriptor or briefly release custody during validation.
    pub fn from_held(store: &'a ProtectedIdentityStore, profile_sha256: &str) -> Result<Self> {
        aegis_core::secure_channel::enrollment::protocol::digest(profile_sha256)?;
        Ok(Self {
            store: HeldStore::Borrowed(store),
            profile_sha256: profile_sha256.to_owned(),
        })
    }

    fn read(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.store.store().read(name)
    }
    fn read_online(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.store.store().read_online(name)
    }
    fn optional<T: serde::de::DeserializeOwned>(&self, name: &str) -> Result<Option<T>> {
        match self.read_online(name) {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("online identity state invalid")?,
            )),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(None)
            }
            Err(error) => Err(error),
        }
    }
    /// Pending and migration files are terminal on mere presence. Keep their
    /// bounded bytes in Zeroizing memory; never deserialize an invitation into
    /// a generic value that lacks the original Pending drop zeroization.
    fn absent(&self, name: &str) -> Result<bool> {
        match self.read_online(name) {
            Ok(_bytes) => Ok(false),
            Err(error)
                if error
                    .downcast_ref::<io::Error>()
                    .is_some_and(|error| error.kind() == io::ErrorKind::NotFound) =>
            {
                Ok(true)
            }
            Err(error) => Err(error),
        }
    }
    fn record(&self) -> Result<Record> {
        let record: Record = serde_json::from_slice(&self.read("identity.json")?)
            .context("device enrollment state is invalid")?;
        registry::validate_device_id(&record.device_id)?;
        ensure!(
            record.version == 1
                && matches!(record.phase.as_str(), "initializing" | "prepared" | "ready"),
            "unsupported device enrollment state"
        );
        Ok(record)
    }
    fn profile(&self) -> Result<()> {
        ensure!(
            std::str::from_utf8(&self.read(PROFILE)?)?.trim() == self.profile_sha256,
            "online profile does not match the durable identity pin"
        );
        ensure!(
            self.absent(MIGRATION)?,
            "profile migration requires exact recovery"
        );
        Ok(())
    }
    fn ensure_idle(&self) -> Result<()> {
        ensure!(
            self.absent(REQUEST)? && self.absent(RESPONSE)? && self.absent(MIGRATION)?,
            "finish the online identity transition before offline completion"
        );
        Ok(())
    }
    fn pinned_ca(&self, record: &Record) -> Result<Vec<u8>> {
        let ca = self.read("device-ca.pem")?;
        ensure!(
            hex::encode(Sha256::digest(&*ca)) == record.device_ca_sha256,
            "pinned device CA has changed"
        );
        Ok(ca.to_vec())
    }
    fn validate_prepared(&self, record: &Record) -> Result<()> {
        self.pinned_ca(record)?;
        let key = self.read("device.key")?;
        let expected = enrollment::csr_for_key(
            &record.device_id,
            std::str::from_utf8(&key).context("device key encoding invalid")?,
        )?;
        ensure!(
            self.read("device.csr")?.as_slice() == expected.as_bytes(),
            "device CSR does not match the local key"
        );
        Ok(())
    }
    fn facts(
        &self,
        record: &Record,
        certificate: &[u8],
    ) -> Result<enrollment::ValidatedDeviceCertificate> {
        let ca = self.pinned_ca(record)?;
        let facts = enrollment::device_certificate_metadata(&record.device_id, certificate, &ca)?;
        enrollment::validate_device_certificate(
            &record.device_id,
            certificate,
            &ca,
            &self.read("device.key")?,
            facts.not_before_unix_secs,
        )?;
        Ok(facts)
    }
    fn validate_response(&self, record: &Record, response: &SavedResponse, now: u64) -> Result<()> {
        ensure!(
            response.version == 1,
            "saved online response version invalid"
        );
        let receipt = &response.receipt;
        receipt.validate()?;
        ensure!(
            receipt.binding.profile_sha256 == self.profile_sha256,
            "online profile does not match the durable identity pin"
        );
        self.profile()?;
        self.validate_prepared(record)?;
        ensure!(
            receipt.device_id == record.device_id
                && receipt.binding.csr_sha256
                    == hex::encode(Sha256::digest(&*self.read("device.csr")?)),
            "response identity or CSR does not match local request"
        );
        let signed = self.facts(record, receipt.certificate_pem.as_bytes())?;
        ensure!(
            signed.fingerprint == receipt.certificate_sha256
                && signed.not_before_unix_secs == receipt.not_before_unix_secs
                && signed.not_after_unix_secs == receipt.not_after_unix_secs,
            "response metadata does not match signed certificate"
        );
        ensure!(
            now >= signed.not_before_unix_secs && now < signed.not_after_unix_secs,
            "response certificate is not currently valid"
        );
        match receipt.binding.operation {
            Operation::Redeem => ensure!(
                response.predecessor_certificate_pem.is_none(),
                "initial response has a predecessor"
            ),
            Operation::Renew => {
                let predecessor = self.facts(
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

    pub fn expectation_at(&self, now: u64) -> Result<OnlineExpectation> {
        self.store.store().revalidate()?;
        self.profile()?;
        self.ensure_idle()?;
        let record = self.record()?;
        ensure!(
            record.phase == "ready",
            "policy acknowledgement requires a completed identity"
        );
        self.validate_prepared(&record)?;
        let current = self.facts(&record, &self.read("device.pem")?)?;
        ensure!(
            record.certificate_sha256.as_ref() == Some(&current.fingerprint)
                && now >= current.not_before_unix_secs
                && now < current.not_after_unix_secs,
            "policy acknowledgement requires the current valid certificate and local key"
        );
        let (issued_generation, snapshot_sha256) =
            if let Some(saved) = self.optional::<SavedResponse>(COMPLETED)? {
                self.validate_response(&record, &saved, now)?;
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
        self.store.store().revalidate()?;
        Ok(OnlineExpectation {
            certificate_sha256: current.fingerprint,
            not_after_unix_secs: current.not_after_unix_secs,
            issued_generation,
            snapshot_sha256,
        })
    }
}
