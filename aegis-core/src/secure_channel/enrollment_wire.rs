//! Bounded enrollment-only messages, used exclusively inside pinned inner TLS.
//! No target, arbitrary URL, file path or certificate policy is accepted here.
use super::enrollment::protocol::{
    self, ChallengeMessage, Operation, ProofPurpose, RequestBinding,
};
use super::registry::validate_device_id;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use zeroize::{Zeroize, Zeroizing};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeRequest {
    pub binding: RequestBinding,
    pub purpose: ProofPurpose,
    pub csr_pem: String,
    pub predecessor_certificate_pem: Option<String>,
    pub invitation: Option<String>,
    pub signature: String,
}

impl Drop for ExchangeRequest {
    fn drop(&mut self) {
        if let Some(invitation) = &mut self.invitation {
            invitation.zeroize();
        }
    }
}

fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid enrollment message")
}

impl ExchangeRequest {
    pub fn validate(&self) -> io::Result<()> {
        self.binding.validate()?;
        if self.csr_pem.is_empty()
            || self.csr_pem.len() > protocol::MAX_CSR_BYTES
            || hex::encode(Sha256::digest(self.csr_pem.as_bytes())) != self.binding.csr_sha256
            || self.signature.len() != 128
            || !self
                .signature
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self
                .predecessor_certificate_pem
                .as_ref()
                .is_some_and(|p| p.is_empty() || p.len() > protocol::MAX_CSR_BYTES)
        {
            return Err(invalid());
        }
        match (self.purpose, self.binding.operation) {
            (ProofPurpose::Authorize, Operation::Redeem) => {
                protocol::digest(self.invitation.as_deref().ok_or_else(invalid)?)?;
                if self.predecessor_certificate_pem.is_some() {
                    return Err(invalid());
                }
            }
            (ProofPurpose::Authorize, Operation::Renew) => {
                if self.invitation.is_some() || self.predecessor_certificate_pem.is_none() {
                    return Err(invalid());
                }
            }
            (ProofPurpose::Receipt, _) => {
                if self.invitation.is_some() || self.predecessor_certificate_pem.is_some() {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }

    pub fn proof_signature(&self) -> io::Result<[u8; 64]> {
        self.validate()?;
        let mut signature = [0; 64];
        hex::decode_to_slice(&self.signature, &mut signature).map_err(|_| invalid())?;
        Ok(signature)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    IssuedPendingDistribution,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentReceipt {
    pub version: u8,
    pub binding: RequestBinding,
    pub device_id: String,
    pub certificate_pem: String,
    pub certificate_sha256: String,
    pub not_before_unix_secs: u64,
    pub not_after_unix_secs: u64,
    pub issued_generation: u64,
    pub snapshot_sha256: String,
    pub state: ReceiptState,
}

impl EnrollmentReceipt {
    /// Structural validation only; clients must separately verify the issuer,
    /// local key, device, profile, lifetime and current relay authorization.
    pub fn validate(&self) -> io::Result<()> {
        self.binding.validate()?;
        validate_device_id(&self.device_id)?;
        protocol::digest(&self.certificate_sha256)?;
        protocol::digest(&self.snapshot_sha256)?;
        if self.version != 1
            || self.certificate_pem.is_empty()
            || self.certificate_pem.len() > protocol::MAX_CSR_BYTES
            || self.not_before_unix_secs == 0
            || self.not_after_unix_secs <= self.not_before_unix_secs
            || self.issued_generation == 0
        {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Fixed public failure classes never include tokens, CSR data, certificate
/// contents, registry records, filesystem paths or issuer error strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureCode {
    Rejected,
    Busy,
    RecoveryRequired,
    Unavailable,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExchangeResponse {
    Issued { receipt: Box<EnrollmentReceipt> },
    Failed { code: FailureCode },
}

async fn read<S: AsyncRead + Unpin, T: DeserializeOwned>(stream: &mut S) -> io::Result<T> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > protocol::MAX_FRAME_BYTES {
        return Err(invalid());
    }
    let mut bytes = Zeroizing::new(vec![0; length]);
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

async fn write<S: AsyncWrite + Unpin, T: Serialize>(stream: &mut S, value: &T) -> io::Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| invalid())?);
    if bytes.is_empty() || bytes.len() > protocol::MAX_FRAME_BYTES {
        return Err(invalid());
    }
    stream.write_u32(bytes.len() as u32).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

pub async fn read_challenge<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<ChallengeMessage> {
    let challenge: ChallengeMessage = read(stream).await?;
    protocol::digest(&challenge.nonce)?;
    if challenge.expires_at_unix_secs == 0 {
        return Err(invalid());
    }
    Ok(challenge)
}

pub async fn write_challenge<S: AsyncWrite + Unpin>(
    stream: &mut S,
    challenge: &ChallengeMessage,
) -> io::Result<()> {
    protocol::digest(&challenge.nonce)?;
    if challenge.expires_at_unix_secs == 0 {
        return Err(invalid());
    }
    write(stream, challenge).await
}

pub async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<ExchangeRequest> {
    let request: ExchangeRequest = read(stream).await?;
    request.validate()?;
    Ok(request)
}

pub async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &ExchangeRequest,
) -> io::Result<()> {
    request.validate()?;
    write(stream, request).await
}

pub async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<ExchangeResponse> {
    let response: ExchangeResponse = read(stream).await?;
    if let ExchangeResponse::Issued { receipt } = &response {
        receipt.validate()?;
    }
    Ok(response)
}

pub async fn write_response<S: AsyncWrite + Unpin>(
    stream: &mut S,
    response: &ExchangeResponse,
) -> io::Result<()> {
    if let ExchangeResponse::Issued { receipt } = response {
        receipt.validate()?;
    }
    write(stream, response).await
}

#[cfg(test)]
#[path = "enrollment_wire_tests.rs"]
mod tests;
