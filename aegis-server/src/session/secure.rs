use aegis_core::auto_capture_probe;
use aegis_core::h2_stream::H2Stream;
use aegis_core::secure_channel::{self, grpc_io::GrpcIo};
use anyhow::Context;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

enum Remote {
    Tcp(tokio::net::TcpStream),
    Udp(tokio::net::UdpSocket),
}

fn establishment_deadline(deadline: tokio::time::Instant) -> std::io::Result<()> {
    if tokio::time::Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "original secure channel establishment deadline elapsed",
        ));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_with_admission(
    request: http::Request<h2::RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    server: secure_channel::Server,
    policy: &crate::config::TargetPolicyConfig,
    rate_limiter: &crate::rate_limit::RateLimiter,
    rate_limit_identity: Option<std::net::IpAddr>,
    activity: Option<super::https_bridge::Activity>,
    privacy: Option<&aegis_core::carrier_runtime::PrivacySettings>,
    training: Option<&secure_channel::relay_shaping::ServerTraining>,
    admission: Option<super::AdmissionBudget>,
    operational_log: crate::operational_log::OperationalLogPolicy,
    grpc_trailers: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        request.method() == http::Method::POST
            && request
                .headers()
                .get("content-type")
                .is_some_and(|h| h == "application/grpc"),
        "invalid secure carrier request"
    );
    let response = http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())?;
    let send = respond.send_response(response, false)?;
    let stream = H2Stream::new(send, request.into_body());
    // CDN gRPC proxies expect a gRPC trailer block at the end of a response.
    let stream = if grpc_trailers {
        stream.with_grpc_ok_trailers()
    } else {
        stream
    };
    let carrier = GrpcIo::new(stream);
    serve_carrier_with_mode(
        carrier,
        server,
        policy,
        rate_limiter,
        rate_limit_identity,
        activity,
        || Ok(()),
        PrivacyMode::Relay(privacy, training),
        admission,
        operational_log,
    )
    .await
}

pub(super) enum PrivacyMode<'a> {
    Opaque(Option<&'a aegis_core::carrier_runtime::PrivacySettings>),
    Relay(
        Option<&'a aegis_core::carrier_runtime::PrivacySettings>,
        Option<&'a secure_channel::relay_shaping::ServerTraining>,
    ),
}

/// Every opaque carrier uses the same device authorization, target policy,
/// revocation watcher and timeout enforcement as the original H2 transport.
#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_carrier<S>(
    carrier: S,
    server: secure_channel::Server,
    policy: &crate::config::TargetPolicyConfig,
    rate_limiter: &crate::rate_limit::RateLimiter,
    rate_limit_identity: Option<std::net::IpAddr>,
    activity: Option<super::https_bridge::Activity>,
    authenticated: impl FnOnce() -> std::io::Result<()>,
    privacy: Option<&aegis_core::carrier_runtime::PrivacySettings>,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    serve_carrier_with_mode(
        carrier,
        server,
        policy,
        rate_limiter,
        rate_limit_identity,
        activity,
        authenticated,
        PrivacyMode::Opaque(privacy),
        None,
        operational_log,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve_carrier_with_mode<S>(
    carrier: S,
    server: secure_channel::Server,
    policy: &crate::config::TargetPolicyConfig,
    rate_limiter: &crate::rate_limit::RateLimiter,
    rate_limit_identity: Option<std::net::IpAddr>,
    activity: Option<super::https_bridge::Activity>,
    authenticated: impl FnOnce() -> std::io::Result<()>,
    privacy: PrivacyMode<'_>,
    admission: Option<super::AdmissionBudget>,
    operational_log: crate::operational_log::OperationalLogPolicy,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    if let PrivacyMode::Opaque(Some(settings)) = &privacy {
        settings.validate_opaque()?;
    }
    // A capacity rejection is not an authentication failure. Check a known ban
    // first so a banned peer cannot consume either admission pool.
    if let Some(identity) = rate_limit_identity {
        if rate_limiter.is_banned(identity).await {
            return Ok(());
        }
    }
    let handshake_permit = server.try_acquire_handshake(rate_limit_identity)?;
    let origin = tokio::time::Instant::now();
    let deadline = admission
        .as_ref()
        .map_or(origin + server.handshake_timeout(), |budget| {
            budget.deadline.min(origin + server.handshake_timeout())
        });
    let authentication_deadline = || {
        if tokio::time::Instant::now() >= deadline {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                secure_channel::AuthenticationFailure::Timeout,
            ))
        } else {
            Ok(())
        }
    };
    authentication_deadline()?;
    let accepted = tokio::time::timeout_at(deadline, server.accept_with_lease(carrier))
        .await
        .unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                secure_channel::AuthenticationFailure::Timeout,
            ))
        })
        .and_then(|accepted| {
            authentication_deadline()?;
            Ok(accepted)
        });
    let (inner, authorization) = match accepted {
        Ok(inner) => inner,
        Err(error) => {
            // A stalled or interrupted transport is not evidence of bad credentials.
            if matches!(
                secure_channel::AuthenticationFailure::from_io(&error),
                Some(
                    secure_channel::AuthenticationFailure::MissingCertificate
                        | secure_channel::AuthenticationFailure::CertificateRejected(_)
                        | secure_channel::AuthenticationFailure::DeviceNotAllowed
                )
            ) {
                if let Some(identity) = rate_limit_identity {
                    rate_limiter.record_failure(identity).await;
                }
            }
            return Err(error.into());
        }
    };
    let _session_permit = server.try_acquire_session(rate_limit_identity)?;
    authentication_deadline()?;
    if let Some(admission) = &admission {
        admission.authenticated()?;
    }
    drop(handshake_permit);
    authenticated()?;
    authentication_deadline()?;
    let _activity = activity
        .as_ref()
        .map(super::https_bridge::Activity::authenticated);
    // The remaining establishment work retains the original total deadline,
    // but an authenticated client's target/open/ACK failure is not an auth
    // failure. Keeping this outside the accept timer also avoids two competing
    // timers hiding the typed authentication-timeout outcome.
    let shaping_owner = aegis_core::carrier_runtime::ShapingCleanupOwner::new();
    let forwarding = async {
        let established = tokio::time::timeout_at(deadline, async {
            establishment_deadline(deadline)?;
            // Negotiation belongs inside the same establishment deadline and
            // live revocation select as Open/ACK. Opaque native carriers retain
            // their existing explicitly configured framing without a hello.
            let (mut inner, liu_context) = match privacy {
                PrivacyMode::Opaque(settings) => (
                    aegis_core::carrier_runtime::shape_authenticated_owned(
                        inner,
                        settings,
                        Some(&shaping_owner),
                    )?,
                    None,
                ),
                PrivacyMode::Relay(settings, training) => {
                    secure_channel::relay_shaping::server_bound_with_training_owned(
                        inner,
                        settings,
                        origin,
                        deadline,
                        training,
                        Some(&shaping_owner),
                    )
                    .await?
                }
            };
            establishment_deadline(deadline)?;
            let open = match secure_channel::policy_ack::read_request(&mut inner).await? {
                secure_channel::policy_ack::ChannelRequest::Open(open) => open,
                secure_channel::policy_ack::ChannelRequest::PolicyAck(request) => {
                    establishment_deadline(deadline)?;
                    if let Some(context) = &liu_context {
                        context.check_policy_ack()?;
                        if inner.read(&mut [0; 1]).await? != 0 {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                "Liu PolicyAck has trailing request data",
                            ));
                        }
                    }
                    establishment_deadline(deadline)?;
                    let ack = authorization.policy_ack(&request.nonce)?;
                    establishment_deadline(deadline)?;
                    secure_channel::policy_ack::write_ack(&mut inner, &ack).await?;
                    inner.shutdown().await?;
                    establishment_deadline(deadline)?;
                    return Ok(None);
                }
            };
            if let Some(context) = &liu_context {
                context.check_open(&open)?;
            }
            establishment_deadline(deadline)?;
            let capture_probe = match open.transport {
                secure_channel::Transport::Tcp => {
                    auto_capture_probe::tcp_target(&open.host, open.port)
                }
                secure_channel::Transport::Udp => {
                    auto_capture_probe::udp_target(&open.host, open.port)
                }
            };
            if capture_probe {
                // This exact numeric tuple is reserved for the installed
                // client's native capture witness. It is admitted only after
                // inner TLS device authorization, never sent to DNS or a
                // target socket, and uses the ordinary Open ACK and carrier.
                let proof_deadline = deadline
                    .min(origin + std::time::Duration::from_secs(auto_capture_probe::MAX_SECONDS));
                tokio::time::timeout_at(proof_deadline, async {
                    inner.write_u8(0).await?;
                    inner.flush().await?;
                    match open.transport {
                        secure_channel::Transport::Tcp => {
                            let mut challenge = [0u8; auto_capture_probe::CHALLENGE_BYTES];
                            inner.read_exact(&mut challenge).await?;
                            inner.write_all(&challenge).await?;
                            inner.flush().await?;
                        }
                        secure_channel::Transport::Udp => {
                            // The ordinary datagram carrier uses a u16 length
                            // prefix. Validate it before allocating or reading
                            // any attacker-sized payload for this fixed proof.
                            let length = inner.read_u16().await? as usize;
                            if length != auto_capture_probe::CHALLENGE_BYTES {
                                return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
                            }
                            let mut challenge = [0u8; auto_capture_probe::CHALLENGE_BYTES];
                            inner.read_exact(&mut challenge).await?;
                            secure_channel::datagram::write(&mut inner, &challenge).await?;
                        }
                    }
                    inner.shutdown().await
                })
                .await??;
                return Ok(None);
            }
            let connected = match open.transport {
                secure_channel::Transport::Tcp => {
                    crate::target_policy::connect_tcp_target_with_logging(
                        &open.host,
                        open.port,
                        policy,
                        operational_log,
                    )
                    .await
                    .map(Remote::Tcp)
                }
                secure_channel::Transport::Udp => {
                    super::secure_udp::connect(&open.host, open.port, policy, operational_log)
                        .await
                        .map(Remote::Udp)
                }
            };
            establishment_deadline(deadline)?;
            let remote = match connected {
                Ok(remote) => remote,
                Err(error) => {
                    inner.write_u8(1).await?;
                    inner.flush().await?;
                    // Preserve the failure ACK when this request finishes:
                    // dropping an open H2 send stream resets queued bytes.
                    inner.shutdown().await?;
                    return Err(error);
                }
            };
            establishment_deadline(deadline)?;
            inner.write_u8(0).await?;
            inner.flush().await?;
            establishment_deadline(deadline)?;
            std::io::Result::Ok(Some((inner, remote)))
        })
        .await
        .context("authenticated secure channel establishment timed out")??;
        let Some((mut inner, mut remote)) = established else {
            return Ok(());
        };
        match &mut remote {
            Remote::Tcp(remote) => {
                secure_channel::copy_with_idle_timeout(&mut inner, remote, server.idle_timeout())
                    .await?;
            }
            Remote::Udp(remote) => {
                super::secure_udp::copy(&mut inner, remote, server.idle_timeout()).await?;
                // A clean datagram input EOF still requires the authenticated
                // output terminator and TLS close_notify before dropping it.
                inner.shutdown().await?;
            }
        }
        anyhow::Ok(())
    };
    // select owns and drops the losing forwarding future before cleanup. The
    // existing permit remains live while the same shaping JoinHandle is joined.
    let result = tokio::select! {
        biased;
        error = authorization.revoked() => Err(error.into()),
        result = forwarding => result,
    };
    let cleanup = shaping_owner
        .cancel_and_join_until(tokio::time::Instant::now() + std::time::Duration::from_millis(500))
        .await;
    match cleanup {
        Ok(observed) => {
            if result.is_ok() {
                if let Some(kind) = observed.worker_error {
                    return Err(
                        std::io::Error::new(kind, "shaping worker ended with a failure").into(),
                    );
                }
            }
            result
        }
        Err(_) => {
            let observed = shaping_owner.observation();
            tracing::warn!(
                registered = observed.registered,
                joined = observed.joined,
                panicked = observed.panicked,
                "shaping cleanup terminal unconfirmed"
            );
            match result {
                Err(error) => Err(error.context("shaping cleanup terminal unconfirmed")),
                Ok(()) => Err(anyhow::anyhow!("shaping cleanup terminal unconfirmed")),
            }
        }
    }
}
