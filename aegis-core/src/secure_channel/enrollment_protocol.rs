//! Enrollment proof bindings. These are application signatures using the
//! existing provider's standard Ed25519 implementation, not a new cipher.
use super::invalid;
use rand::RngCore;
use rcgen::PublicKeyData;
use rustls::pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};
use std::io;
use std::time::{Duration, Instant};

pub const MAX_CSR_BYTES: usize = 64 * 1024;
pub const MAX_FRAME_BYTES: usize = 128 * 1024;
pub const CHALLENGE_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Redeem,
    Renew,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofPurpose {
    Authorize,
    Receipt,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestBinding {
    pub operation: Operation,
    pub request_id: String,
    pub profile_sha256: String,
    pub csr_sha256: String,
    pub predecessor_sha256: Option<String>,
}

pub fn digest(value: &str) -> io::Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("enrollment digest or request identifier invalid"));
    }
    let mut bytes = [0; 32];
    hex::decode_to_slice(value, &mut bytes).map_err(|_| invalid("enrollment digest invalid"))?;
    Ok(bytes)
}

impl RequestBinding {
    pub fn validate(&self) -> io::Result<()> {
        digest(&self.request_id)?;
        digest(&self.profile_sha256)?;
        digest(&self.csr_sha256)?;
        match (self.operation, &self.predecessor_sha256) {
            (Operation::Redeem, None) => {}
            (Operation::Renew, Some(value)) => {
                digest(value)?;
            }
            _ => return Err(invalid("enrollment predecessor does not match operation")),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeMessage {
    pub nonce: String,
    pub expires_at_unix_secs: u64,
}

/// This object belongs to exactly one already authenticated inner-TLS
/// connection. A failed attempt also consumes it. Do not serialize or clone it.
pub struct ConnectionChallenge {
    nonce: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    deadline: Instant,
    consumed: bool,
}

pub struct VerifiedProof {
    binding: RequestBinding,
    purpose: ProofPurpose,
    public_key: [u8; 32],
    issued_at: u64,
    expires_at: u64,
    deadline: Instant,
}

impl VerifiedProof {
    pub fn check(
        &self,
        binding: &RequestBinding,
        public_key: &[u8; 32],
        now: u64,
        new_issuance: bool,
    ) -> io::Result<()> {
        if &self.binding != binding
            || &self.public_key != public_key
            || now < self.issued_at
            || now >= self.expires_at
            || Instant::now() >= self.deadline
            || (new_issuance && self.purpose != ProofPurpose::Authorize)
        {
            return Err(invalid(
                "enrollment proof is expired or does not match request",
            ));
        }
        Ok(())
    }
}

impl ConnectionChallenge {
    pub fn new(now: u64) -> io::Result<Self> {
        if now == 0 {
            return Err(invalid("enrollment clock invalid"));
        }
        let mut nonce = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok(Self {
            nonce,
            issued_at: now,
            expires_at: now
                .checked_add(CHALLENGE_SECS)
                .ok_or_else(|| invalid("enrollment clock overflow"))?,
            deadline: Instant::now() + Duration::from_secs(CHALLENGE_SECS),
            consumed: false,
        })
    }

    pub fn message(&self) -> ChallengeMessage {
        ChallengeMessage {
            nonce: hex::encode(self.nonce),
            expires_at_unix_secs: self.expires_at,
        }
    }

    pub fn verify(
        &mut self,
        binding: &RequestBinding,
        purpose: ProofPurpose,
        public_key: &[u8; 32],
        signature: &[u8],
        now: u64,
    ) -> io::Result<VerifiedProof> {
        if std::mem::replace(&mut self.consumed, true)
            || now < self.issued_at
            || now >= self.expires_at
            || Instant::now() >= self.deadline
        {
            return Err(invalid("enrollment challenge expired or consumed"));
        }
        verify_ed25519(
            public_key,
            &transcript(&self.message(), binding, purpose)?,
            signature,
        )?;
        Ok(VerifiedProof {
            binding: binding.clone(),
            purpose,
            public_key: *public_key,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
            deadline: self.deadline,
        })
    }
}

fn transcript(
    challenge: &ChallengeMessage,
    binding: &RequestBinding,
    purpose: ProofPurpose,
) -> io::Result<Vec<u8>> {
    binding.validate()?;
    let nonce = digest(&challenge.nonce)?;
    let mut bytes = b"AEGIS-ENROLLMENT-ED25519-PROOF-V1\0".to_vec();
    for field in [
        match purpose {
            ProofPurpose::Authorize => b"authorize".as_slice(),
            ProofPurpose::Receipt => b"receipt".as_slice(),
        },
        match binding.operation {
            Operation::Redeem => b"redeem".as_slice(),
            Operation::Renew => b"renew".as_slice(),
        },
        nonce.as_slice(),
        binding.request_id.as_bytes(),
        binding.profile_sha256.as_bytes(),
        binding.csr_sha256.as_bytes(),
        binding
            .predecessor_sha256
            .as_deref()
            .unwrap_or("")
            .as_bytes(),
        &challenge.expires_at_unix_secs.to_be_bytes(),
    ] {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    Ok(bytes)
}

pub fn sign_proof(
    key_pem: &[u8],
    challenge: &ChallengeMessage,
    binding: &RequestBinding,
    purpose: ProofPurpose,
    now: u64,
) -> io::Result<Vec<u8>> {
    if key_pem.len() > MAX_CSR_BYTES
        || challenge.expires_at_unix_secs <= now
        || challenge.expires_at_unix_secs > now.saturating_add(CHALLENGE_SECS)
    {
        return Err(invalid("enrollment challenge or key input invalid"));
    }
    let key = rustls::pki_types::PrivateKeyDer::from_pem_slice(key_pem)
        .map_err(|_| invalid("device key invalid"))?;
    let signer = super::super::provider()
        .key_provider
        .load_private_key(key)
        .map_err(|_| invalid("device key invalid"))?;
    signer
        .choose_scheme(&[rustls::SignatureScheme::ED25519])
        .ok_or_else(|| invalid("enrollment requires Ed25519"))?
        .sign(&transcript(challenge, binding, purpose)?)
        .map_err(|_| invalid("enrollment proof signing failed"))
}

fn verify_ed25519(public_key: &[u8; 32], message: &[u8], signature: &[u8]) -> io::Result<()> {
    if signature.len() != 64 {
        return Err(invalid("enrollment proof signature invalid"));
    }
    let provider = super::super::provider();
    let algorithms = provider
        .signature_verification_algorithms
        .mapping
        .iter()
        .find(|(scheme, _)| *scheme == rustls::SignatureScheme::ED25519)
        .ok_or_else(|| invalid("Ed25519 provider unavailable"))?
        .1;
    let algorithm = algorithms
        .first()
        .ok_or_else(|| invalid("Ed25519 provider unavailable"))?;
    algorithm
        .verify_signature(public_key, message, signature)
        .map_err(|_| invalid("enrollment proof rejected"))
}

/// Verify the existing CSR signature and return its standard Ed25519 key.
/// Requested usages/names remain untrusted; issuer policy selects those fields.
pub fn csr_public_key(csr: &str) -> io::Result<[u8; 32]> {
    let text = csr.trim();
    if csr.len() > MAX_CSR_BYTES
        || !text.starts_with("-----BEGIN CERTIFICATE REQUEST-----")
        || !text.ends_with("-----END CERTIFICATE REQUEST-----")
        || text.matches("-----BEGIN").count() != 1
    {
        return Err(invalid("only one bounded public CSR is accepted"));
    }
    let parsed = rcgen::CertificateSigningRequestParams::from_pem(text)
        .map_err(|_| invalid("CSR signature invalid"))?;
    if parsed.public_key.algorithm() != &rcgen::PKCS_ED25519 {
        return Err(invalid("enrollment requires Ed25519"));
    }
    parsed
        .public_key
        .der_bytes()
        .try_into()
        .map_err(|_| invalid("CSR key invalid"))
}

#[cfg(test)]
#[path = "enrollment_protocol_tests.rs"]
mod tests;
