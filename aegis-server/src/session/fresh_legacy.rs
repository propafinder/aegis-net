//! Raw-only opt-in adapter; setup permission and target policy stay with the server.
use super::{legacy_tcp, AdmissionBudget, TunnelAuthKey, TunnelAuthKeyring};
use crate::config::{ServerLimits, TargetPolicyConfig};
use crate::rate_limit::RateLimiter;
use aegis_core::tunnel::fresh_legacy::{admit_raw, KeyCandidate};
use aegis_core::tunnel::{TunnelResponse, TunnelStatus};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

// Take the monotonic snapshot first: converting the remaining wall-clock lease
// can only shorten setup. Wall-clock steps/RNG state restoration remain external
// trust assumptions, not claims of this cooperative admission mechanism.
fn expiry_deadline(key: &TunnelAuthKey) -> Option<Instant> {
    let expires = key.not_after_unix_secs?;
    let monotonic = Instant::now();
    let wall = SystemTime::now();
    let remaining = SystemTime::UNIX_EPOCH
        .checked_add(Duration::from_secs(expires))
        .and_then(|end| end.duration_since(wall).ok())
        .unwrap_or(Duration::ZERO);
    monotonic.checked_add(remaining)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle<S>(
    stream: &mut S,
    keyring: &TunnelAuthKeyring,
    limits: &ServerLimits,
    target_policy: &TargetPolicyConfig,
    rate_limiter: &RateLimiter,
    peer: SocketAddr,
    admission: AdmissionBudget,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let opened = open_target(stream, keyring, limits, target_policy, peer, &admission).await;
    let Some(mut remote) = (match opened {
        Ok(remote) => remote,
        Err(error) => {
            let authentication_failure = matches!(&error, aegis_core::AegisError::Auth);
            let propagate = matches!(&error, aegis_core::AegisError::Io(_))
                || matches!(&error, aegis_core::AegisError::RelayCodec(message)
                    if message == "fresh legacy admission deadline expired");
            let error = match error {
                aegis_core::AegisError::Io(error) => anyhow::Error::from(error),
                aegis_core::AegisError::RelayCodec(message)
                    if message == "fresh legacy admission deadline expired" =>
                {
                    anyhow::Error::from(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
                }
                error => anyhow::Error::from(error),
            };
            crate::operational_log::debug_failure(
                keyring.operational_log(),
                crate::operational_log::FailureStage::TcpSession,
                crate::operational_log::FailureReason::RequestFailed,
                Some(peer),
                &error,
            );
            // Refuse wrong/old protocol without contact to a fallback proxy.
            // Keep the same original budget even for failure bookkeeping.
            if authentication_failure {
                let _ = tokio::time::timeout_at(
                    admission.deadline,
                    rate_limiter.record_socket_failure(peer),
                )
                .await;
            }
            // Wrong/old protocol and malformed admission still close quietly.
            // Actual I/O and the private core deadline retain the handler's
            // operational error contract instead of being reported as success.
            if propagate {
                return Err(error);
            }
            return Ok(());
        }
    }) else {
        return Ok(());
    };
    match legacy_tcp::forward(
        stream,
        &mut remote,
        Duration::from_millis(limits.legacy_tcp_idle_timeout_ms),
        Duration::from_millis(limits.write_timeout_ms),
    )
    .await
    {
        Ok(_) => Ok(()),
        Err(error) => {
            let error = anyhow::Error::from(error);
            if super::benign_io_close(&error) {
                return Ok(());
            }
            Err(error)
        }
    }
}

async fn open_target<S>(
    stream: &mut S,
    keyring: &TunnelAuthKeyring,
    limits: &ServerLimits,
    target_policy: &TargetPolicyConfig,
    peer: SocketAddr,
    admission: &AdmissionBudget,
) -> aegis_core::Result<Option<tokio::net::TcpStream>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let keys = keyring
        .keys
        .iter()
        .map(|key| KeyCandidate {
            authority: key,
            secret: key.secret(),
            expires: expiry_deadline(key),
        })
        .collect::<Vec<_>>();
    admit_raw(
        stream,
        &keys,
        admission.deadline,
        Duration::from_millis(limits.write_timeout_ms),
        |key| key.is_active_at(super::unix_time_now()),
        |request, key| async move {
            if request.host.len() > limits.max_host_len {
                return Ok((
                    None,
                    TunnelResponse {
                        status: TunnelStatus::BadTarget,
                        message: "target host length exceeds limit".into(),
                    },
                ));
            }
            // Only a valid proof releases the socket setup permit. No DNS or
            // target-policy connector has even been constructed before this.
            admission.authenticated()?;
            keyring.log_accept(key, peer, "fresh_legacy_tls");
            let established = legacy_tcp::establish(
                crate::target_policy::connect_tcp_target_with_logging(
                    &request.host,
                    request.port,
                    target_policy,
                    keyring.operational_log(),
                ),
                Duration::from_millis(limits.legacy_tcp_connect_timeout_ms),
            )
            .await;
            Ok(match established {
                Ok(remote) => (
                    Some(remote),
                    TunnelResponse {
                        status: TunnelStatus::Ok,
                        message: String::new(),
                    },
                ),
                Err(error) => (
                    None,
                    TunnelResponse {
                        status: super::classify_connect_failure_status(&error),
                        message: "legacy target establishment failed".into(),
                    },
                ),
            })
        },
    )
    .await
}

#[cfg(test)]
#[path = "fresh_legacy/tests.rs"]
mod tests;
