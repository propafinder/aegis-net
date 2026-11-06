//! Targetless policy acknowledgement inside the existing device-authenticated
//! TLS channel. A fresh nonce binds the reply to this connection's request.
use super::{invalid, OpenRequest};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_BYTES: usize = 1024;

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    PolicyAck,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyAckRequest {
    version: u8,
    operation: Operation,
    pub nonce: String,
}

impl PolicyAckRequest {
    pub fn new() -> Self {
        use rand::RngCore;
        let mut bytes = [0; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self {
            version: 1,
            operation: Operation::PolicyAck,
            nonce: hex::encode(bytes),
        }
    }

    fn validate(&self) -> io::Result<()> {
        if self.version != 1 || !digest(&self.nonce) {
            return Err(invalid("invalid policy acknowledgement request"));
        }
        Ok(())
    }
}

impl Default for PolicyAckRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum ChannelRequest {
    Open(OpenRequest),
    PolicyAck(PolicyAckRequest),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimePolicyAck {
    pub version: u8,
    pub nonce: String,
    pub generation: u64,
    pub snapshot_sha256: String,
    pub certificate_sha256: String,
    pub policy_not_after_unix_secs: u64,
    pub certificate_not_after_unix_secs: u64,
    pub effective_valid_for_ms: u64,
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl RuntimePolicyAck {
    fn validate(&self) -> io::Result<()> {
        if self.version != 1
            || self.generation == 0
            || !digest(&self.nonce)
            || !digest(&self.snapshot_sha256)
            || !digest(&self.certificate_sha256)
            || self.policy_not_after_unix_secs == 0
            || self.certificate_not_after_unix_secs == 0
            || !(1..=super::registry::MAX_STALENESS.as_millis() as u64)
                .contains(&self.effective_valid_for_ms)
        {
            return Err(invalid("invalid runtime policy acknowledgement"));
        }
        Ok(())
    }

    /// Newer live snapshots may include other devices' changes. The same
    /// generation must have the exact retained receipt's digest. The peer must
    /// always authorize the current certificate, including after migration.
    /// `elapsed` spans request write through reply verification on the client's
    /// monotonic clock, so a carrier cannot make a delayed reply look fresh.
    pub fn verify(
        &self,
        nonce: &str,
        certificate_sha256: &str,
        minimum: Option<(u64, &str)>,
        now: u64,
        elapsed: std::time::Duration,
    ) -> io::Result<std::time::Duration> {
        self.validate()?;
        if self.nonce != nonce
            || self.certificate_sha256 != certificate_sha256
            || now >= self.policy_not_after_unix_secs
            || now >= self.certificate_not_after_unix_secs
            || elapsed >= std::time::Duration::from_millis(self.effective_valid_for_ms)
            || minimum.is_some_and(|(generation, digest)| {
                generation == 0
                    || !self::digest(digest)
                    || self.generation < generation
                    || (self.generation == generation && self.snapshot_sha256 != digest)
            })
        {
            return Err(invalid(
                "runtime policy does not confirm current device issuance",
            ));
        }
        Ok(std::time::Duration::from_millis(self.effective_valid_for_ms) - elapsed)
    }
}

async fn read<S: AsyncRead + Unpin, T: DeserializeOwned>(stream: &mut S) -> io::Result<T> {
    let length = stream.read_u16().await? as usize;
    if length == 0 || length > MAX_BYTES {
        return Err(invalid("policy control frame exceeds bound"));
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes).map_err(|_| invalid("invalid policy control frame"))
}

async fn write<S: AsyncWrite + Unpin, T: Serialize>(stream: &mut S, value: &T) -> io::Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid("invalid policy control frame"))?;
    if bytes.is_empty() || bytes.len() > MAX_BYTES {
        return Err(invalid("policy control frame exceeds bound"));
    }
    stream.write_u16(bytes.len() as u16).await?;
    stream.write_all(&bytes).await?;
    stream.flush().await
}

pub async fn read_request<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<ChannelRequest> {
    let request = read(stream).await?;
    match &request {
        ChannelRequest::Open(open) => open.validate()?,
        ChannelRequest::PolicyAck(ack) => ack.validate()?,
    }
    Ok(request)
}

pub async fn write_request<S: AsyncWrite + Unpin>(
    stream: &mut S,
    request: &PolicyAckRequest,
) -> io::Result<()> {
    request.validate()?;
    write(stream, request).await
}

pub async fn read_ack<S: AsyncRead + Unpin>(stream: &mut S) -> io::Result<RuntimePolicyAck> {
    let ack: RuntimePolicyAck = read(stream).await?;
    ack.validate()?;
    Ok(ack)
}

pub async fn write_ack<S: AsyncWrite + Unpin>(
    stream: &mut S,
    ack: &RuntimePolicyAck,
) -> io::Result<()> {
    ack.validate()?;
    write(stream, ack).await
}

#[cfg(test)]
#[path = "policy_ack_tests.rs"]
mod tests;
