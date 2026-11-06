//! Targetless policy ACK exchange on a caller-owned, already authenticated
//! inner TLS stream. The stream's transport and device identity remain the
//! caller's responsibility; this operation cannot grant packet capture.

use crate::{issuance_binding::IssuanceBinding, policy_ack_binding::verify_observed_ack};
use aegis_core::secure_channel::{policy_ack, registry};
use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};

/// Send a fresh nonce, read one ACK and bind its expiry to the same request.
/// `half_close_request` preserves the Liu channel's request-end signal.
/// The caller must enforce its overall transport deadline around this future.
pub async fn exchange_on_authenticated_stream<S>(
    stream: &mut S,
    expected: IssuanceBinding<'_>,
    half_close_request: bool,
) -> Result<tokio::time::Instant>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let request = policy_ack::PolicyAckRequest::new();
    let requested = tokio::time::Instant::now();
    policy_ack::write_request(stream, &request).await?;
    if half_close_request {
        stream.shutdown().await?;
    }
    let ack = policy_ack::read_ack(stream).await?;
    let valid_for = verify_observed_ack(
        &ack,
        &request.nonce,
        expected,
        registry::unix_now()?,
        requested.elapsed(),
    )?;
    Ok(requested + valid_for)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::secure_channel::policy_ack::{ChannelRequest, RuntimePolicyAck};
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    const CERT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const SNAPSHOT: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn expected(expiry: u64) -> IssuanceBinding<'static> {
        IssuanceBinding {
            certificate_sha256: CERT,
            not_after_unix_secs: expiry,
            issued_generation: Some(7),
            snapshot_sha256: Some(SNAPSHOT),
        }
    }

    fn reply(nonce: String, expiry: u64) -> RuntimePolicyAck {
        RuntimePolicyAck {
            version: 1,
            nonce,
            generation: 7,
            snapshot_sha256: SNAPSHOT.into(),
            certificate_sha256: CERT.into(),
            policy_not_after_unix_secs: expiry,
            certificate_not_after_unix_secs: expiry,
            effective_valid_for_ms: 3_000,
        }
    }

    #[tokio::test]
    async fn actual_request_nonce_and_half_close_bind_one_reply() {
        let expiry = registry::unix_now().unwrap() + 60;
        let (mut client, mut peer) = tokio::io::duplex(2048);
        let server = tokio::spawn(async move {
            let ChannelRequest::PolicyAck(request) =
                policy_ack::read_request(&mut peer).await.unwrap()
            else {
                panic!("targetless ACK request required");
            };
            let mut eof = [0u8; 1];
            assert_eq!(peer.read(&mut eof).await.unwrap(), 0);
            policy_ack::write_ack(&mut peer, &reply(request.nonce, expiry))
                .await
                .unwrap();
        });
        let before = tokio::time::Instant::now();
        let deadline = exchange_on_authenticated_stream(&mut client, expected(expiry), true)
            .await
            .unwrap();
        let after = tokio::time::Instant::now();
        server.await.unwrap();
        assert!(deadline > after);
        assert!(deadline > before);
        assert!(deadline <= after + Duration::from_secs(3));
    }

    #[tokio::test]
    async fn changed_issuance_and_replayed_nonce_refuse() {
        let expiry = registry::unix_now().unwrap() + 60;
        for replay_nonce in [false, true] {
            let (mut client, mut peer) = tokio::io::duplex(2048);
            let server = tokio::spawn(async move {
                let ChannelRequest::PolicyAck(request) =
                    policy_ack::read_request(&mut peer).await.unwrap()
                else {
                    panic!("targetless ACK request required");
                };
                let mut ack = reply(request.nonce, expiry);
                if replay_nonce {
                    ack.nonce =
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into();
                } else {
                    ack.snapshot_sha256 =
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd".into();
                }
                policy_ack::write_ack(&mut peer, &ack).await.unwrap();
            });
            assert!(
                exchange_on_authenticated_stream(&mut client, expected(expiry), false)
                    .await
                    .is_err()
            );
            server.await.unwrap();
        }
    }
}
