//! B-06 S22: provider-side identity custody over held bytes.
//!
//! The provider capture holds `device.csr` and `online-completed.json` beside
//! the record, key and certificate, and requires the online transaction
//! journal (`online-request.json`, `online-response.json`,
//! `online-profile-migration.json`) to be absent. Over those exact held bytes
//! the provider itself
//! - re-derives `csr_for_key(record.device_id, held key)` and requires the
//!   held CSR byte for byte, so the key, the device id and the CSR are bound;
//! - parses the held completion receipt and binds it to the held record, the
//!   held CSR, the held public profile digest and the held certificate bytes;
//! - later requires the protected Store's returned `OnlineExpectation` to name
//!   exactly that receipt's certificate, lifetime, generation and snapshot.
//!
//! No Store accessor is added: these checks read only what the capture holds.
//! An identity without a completed issuance is never admitted on this path.
//! Nothing here is a relay ACK, packet permit or start request.
use aegis_client::online_expectation::OnlineExpectation;
use aegis_core::secure_channel::{
    enrollment::{self, protocol::Operation},
    enrollment_wire::EnrollmentReceipt,
    registry,
};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// The held CSR is not `csr_for_key(record.device_id, held key)`.
pub(crate) const CSR_MISMATCH: &str = "identity_csr_mismatch";
/// The held `identity.json` is not a ready version-1 record.
pub(crate) const RECORD_REFUSED: &str = "identity_record_refused";
/// The held completion receipt is malformed or names another device, CSR,
/// profile or certificate.
pub(crate) const COMPLETION_REFUSED: &str = "identity_completion_refused";
/// An online request, response or profile migration is in the held directory.
pub(crate) const JOURNAL_PENDING: &str = "identity_journal_pending";
/// The Store's expectation is not the held receipt's issuance.
pub(crate) const ISSUANCE_MISMATCH: &str = "identity_issuance_mismatch";

/// Leaves whose mere presence refuses a capture: an unfinished online
/// transition or profile migration, exactly the Store's terminal set.
pub(crate) const JOURNAL: [&str; 3] = [
    "online-request.json",
    "online-response.json",
    "online-profile-migration.json",
];

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn exact<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a serde_json::Map<String, Value>> {
    let object = value.as_object()?;
    (object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key)))
        .then_some(object)
}

/// The exact held identity bytes one check runs over.
pub(crate) struct HeldIdentityBytes<'a> {
    pub(crate) record: &'a [u8],
    pub(crate) key: &'a [u8],
    pub(crate) csr: &'a [u8],
    pub(crate) certificate: &'a [u8],
    /// S23: the held `device-ca.pem` the record pins.
    pub(crate) device_ca: &'a [u8],
    pub(crate) completion: &'a [u8],
}

/// The issuance a held completion receipt names. It is data derived from
/// held bytes, not evidence that a Store or relay admitted it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HeldIssuance {
    certificate_sha256: String,
    // S23: the receipt's validity window, bound at capture to the held
    // certificate's own signed validity (`verify`).
    not_before_unix_secs: u64,
    not_after_unix_secs: u64,
    issued_generation: u64,
    snapshot_sha256: String,
}

struct Record {
    device_id: String,
    device_ca_sha256: String,
    certificate_sha256: String,
}

fn record(bytes: &[u8]) -> Result<Record, &'static str> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| RECORD_REFUSED)?;
    let object = exact(
        &value,
        &[
            "version",
            "device_id",
            "phase",
            "device_ca_sha256",
            "certificate_sha256",
        ],
    )
    .ok_or(RECORD_REFUSED)?;
    let text = |key: &str| object[key].as_str().ok_or(RECORD_REFUSED);
    if object["version"].as_u64() != Some(1) || text("phase")? != "ready" {
        return Err(RECORD_REFUSED);
    }
    let device_id = text("device_id")?.to_owned();
    registry::validate_device_id(&device_id).map_err(|_| RECORD_REFUSED)?;
    let device_ca_sha256 = text("device_ca_sha256")?.to_owned();
    enrollment::protocol::digest(&device_ca_sha256).map_err(|_| RECORD_REFUSED)?;
    let certificate_sha256 = text("certificate_sha256")?.to_owned();
    enrollment::protocol::digest(&certificate_sha256).map_err(|_| RECORD_REFUSED)?;
    Ok(Record {
        device_id,
        device_ca_sha256,
        certificate_sha256,
    })
}

/// Check the held identity bytes against each other and against the held
/// public profile digest `profile_sha256`; return the receipt's issuance.
pub(crate) fn verify(
    held: &HeldIdentityBytes<'_>,
    profile_sha256: &str,
) -> Result<HeldIssuance, &'static str> {
    let record = record(held.record)?;
    // Key, device id and CSR: the CSR must be the one this key signs for this
    // device id. Ed25519 and the fixed CSR encoding make this deterministic.
    let key = std::str::from_utf8(held.key).map_err(|_| CSR_MISMATCH)?;
    let expected = enrollment::csr_for_key(&record.device_id, key).map_err(|_| CSR_MISMATCH)?;
    if held.csr != expected.as_bytes() {
        return Err(CSR_MISMATCH);
    }

    let refused = COMPLETION_REFUSED;
    let value: Value = serde_json::from_slice(held.completion).map_err(|_| refused)?;
    let saved = exact(
        &value,
        &["version", "receipt", "predecessor_certificate_pem"],
    )
    .ok_or(refused)?;
    if saved["version"].as_u64() != Some(1) {
        return Err(refused);
    }
    let predecessor = match &saved["predecessor_certificate_pem"] {
        Value::Null => false,
        Value::String(text) if !text.is_empty() => true,
        _ => return Err(refused),
    };
    let receipt: EnrollmentReceipt =
        serde_json::from_value(saved["receipt"].clone()).map_err(|_| refused)?;
    receipt.validate().map_err(|_| refused)?;
    let binding = &receipt.binding;
    if receipt.device_id != record.device_id
        || binding.csr_sha256 != sha256_hex(held.csr)
        || binding.profile_sha256 != profile_sha256
        || receipt.certificate_sha256 != record.certificate_sha256
        || receipt.certificate_pem.as_bytes() != held.certificate
        || predecessor != (binding.operation == Operation::Renew)
    {
        return Err(refused);
    }
    // S23: the receipt's window is trusted (an expired identity is judged
    // from it before the Store opens) only once it is the held certificate's
    // own signed validity, under the device CA the record pins. A receipt
    // edited to any other window stays the terminal refusal of tampering.
    if sha256_hex(held.device_ca) != record.device_ca_sha256 {
        return Err(refused);
    }
    let signed = enrollment::device_certificate_metadata(
        &record.device_id,
        held.certificate,
        held.device_ca,
    )
    .map_err(|_| refused)?;
    if signed.fingerprint != receipt.certificate_sha256
        || signed.not_before_unix_secs != receipt.not_before_unix_secs
        || signed.not_after_unix_secs != receipt.not_after_unix_secs
    {
        return Err(refused);
    }
    Ok(HeldIssuance {
        certificate_sha256: receipt.certificate_sha256,
        not_before_unix_secs: receipt.not_before_unix_secs,
        not_after_unix_secs: receipt.not_after_unix_secs,
        issued_generation: receipt.issued_generation,
        snapshot_sha256: receipt.snapshot_sha256,
    })
}

impl HeldIssuance {
    /// S23: the held receipt's `(not_before, not_after)`, unix seconds.
    pub(crate) fn window(&self) -> (u64, u64) {
        (self.not_before_unix_secs, self.not_after_unix_secs)
    }

    /// Require the Store's returned expectation to be exactly this receipt's
    /// issuance: certificate, lifetime, a present generation and snapshot.
    pub(crate) fn ensure_matches(&self, online: &OnlineExpectation) -> Result<(), &'static str> {
        if online.certificate_sha256 != self.certificate_sha256
            || online.not_after_unix_secs != self.not_after_unix_secs
            || online.issued_generation != Some(self.issued_generation)
            || online.snapshot_sha256.as_deref() != Some(self.snapshot_sha256.as_str())
        {
            return Err(ISSUANCE_MISMATCH);
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "identity_custody_tests.rs"]
mod tests;
