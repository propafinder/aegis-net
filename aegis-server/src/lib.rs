//! AEGIS relay server: TLS accept, tunnel, rate limiting, graceful shutdown.
//!
//! M2 changes vs v1:
//! - Semaphore for max concurrent connections
//! - Graceful shutdown on SIGTERM/SIGINT
//! - Rate limiter integration
//! - Background cleanup task for rate limiter

pub mod bundle_token_status;
pub mod bundle_tokens;
pub mod carrier;
pub mod config;
pub mod device_policy;
mod device_policy_status;
pub mod devices;
pub mod enrollment_service;
pub mod enrollment_store;
mod lifecycle;
mod operational_log;
#[cfg(test)]
mod operational_log_tests;

/// Emit a process-alias failure under the configured operational privacy policy.
pub fn log_process_alias_failure(
    logging: &config::OperationalLoggingConfig,
    alias: &str,
    error: &(impl std::fmt::Display + ?Sized),
) {
    operational_log::warn_process_alias_failure(logging.policy(), alias, error);
}
pub mod phase_witness;
pub mod rate_limit;
pub mod session;
#[cfg(feature = "webrtc-carrier")]
#[allow(dead_code)] // No SFU token issuer or media worker is wired yet.
mod sfu_bootstrap;
pub mod target_policy;
pub mod tls;
#[cfg(feature = "webrtc-carrier")]
pub mod webrtc;

use anyhow::Context;
use lifecycle::{drain_tasks, OwnedTask};
use rate_limit::RateLimiter;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::TlsAcceptor;

pub(crate) fn connection_permit_limit(configured: usize) -> usize {
    let runtime_max = Semaphore::MAX_PERMITS.min(u32::MAX as usize);
    if configured == 0 {
        runtime_max
    } else {
        configured.min(runtime_max)
    }
}

pub async fn run_server(cfg: config::ServerConfig) -> anyhow::Result<()> {
    run_server_with_ready(cfg, None).await
}

/// Signal readiness after all required listeners bind. QUIC is required by
/// default; an explicitly optional QUIC deployment can report TCP-only ready.
pub async fn run_server_with_ready(
    cfg: config::ServerConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
) -> anyhow::Result<()> {
    let shutdown = lifecycle::shutdown_signal().context("register server shutdown signals")?;
    run_server_with_shutdown(cfg, ready, shutdown).await
}

/// Opt-in local startup aggregate with the ordinary readiness and shutdown
/// contract. The caller retains the witness and decides whether to expose its
/// snapshot; the server itself performs no logging for it.
pub async fn run_server_with_ready_and_witness(
    cfg: config::ServerConfig,
    ready: tokio::sync::oneshot::Sender<()>,
    witness: phase_witness::ServerPhaseWitness,
) -> anyhow::Result<()> {
    let shutdown = lifecycle::shutdown_signal().context("register server shutdown signals")?;
    run_server_with_readiness(
        cfg,
        Some(Readiness::Unit(ready)),
        Some(witness),
        async move {
            shutdown.await;
            Ok(())
        },
    )
    .await
}

/// Library/test entry point with an explicitly owned shutdown trigger.
pub async fn run_server_with_shutdown(
    cfg: config::ServerConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    run_server_with_stop(cfg, ready, async move {
        shutdown.await;
        Ok(())
    })
    .await
}

/// Like `run_server_with_shutdown`, but reports the kernel-selected TCP address
/// after every required listener is ready. This supports port-zero library
/// callers without releasing a reservation and racing a second bind.
pub async fn run_server_with_bound_ready_and_shutdown(
    cfg: config::ServerConfig,
    ready: tokio::sync::oneshot::Sender<std::net::SocketAddr>,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    run_server_with_readiness(cfg, Some(Readiness::Address(ready)), None, async move {
        shutdown.await;
        Ok(())
    })
    .await
}

/// Owned local diagnostics alongside actual bound readiness and shutdown.
/// The witness records static aggregate phases, never authentication or wire
/// delivery. Ordinary server entry points leave it disabled.
pub async fn run_server_with_bound_ready_shutdown_and_witness(
    cfg: config::ServerConfig,
    ready: tokio::sync::oneshot::Sender<std::net::SocketAddr>,
    shutdown: impl std::future::Future<Output = ()>,
    witness: phase_witness::ServerPhaseWitness,
) -> anyhow::Result<()> {
    run_server_with_readiness(
        cfg,
        Some(Readiness::Address(ready)),
        Some(witness),
        async move {
            shutdown.await;
            Ok(())
        },
    )
    .await
}

enum Readiness {
    Unit(tokio::sync::oneshot::Sender<()>),
    Address(tokio::sync::oneshot::Sender<std::net::SocketAddr>),
}

// The fallible stop seam also lets unit tests inject a controlled runtime
// ingress failure without sabotaging a real listener or exposing a public API.
async fn run_server_with_stop(
    cfg: config::ServerConfig,
    ready: Option<tokio::sync::oneshot::Sender<()>>,
    stop: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    run_server_with_readiness(cfg, ready.map(Readiness::Unit), None, stop).await
}

async fn run_server_with_readiness(
    cfg: config::ServerConfig,
    ready: Option<Readiness>,
    witness: Option<phase_witness::ServerPhaseWitness>,
    stop: impl std::future::Future<Output = anyhow::Result<()>>,
) -> anyhow::Result<()> {
    tokio::pin!(stop);
    // Validate the bounded keyring before opening any network surface. Main
    // loads from disk first, but library callers can construct ServerConfig
    // directly and must receive the same fail-closed behavior.
    let auth =
        session::TunnelAuthKeyring::from_config_for_startup_with_observer(&cfg, witness.as_ref())
            .await?;
    let mut device_registry_watcher = auth
        .inner_tls
        .as_ref()
        .and_then(|server| server.start_registry_watcher());
    let scfg = tls::load_server_config(&cfg.cert, &cfg.key)?;
    let acceptor = TlsAcceptor::from(scfg);
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("bind {}", cfg.listen))?;
    let bound_address = listener.local_addr().context("read TCP listener address")?;
    operational_log::info_listener_bound(cfg.logging.policy(), bound_address);

    let fallback = cfg.fallback.clone();
    let limits = Arc::new(cfg.limits.clone());
    let transport = Arc::new(cfg.transport.clone());
    let target_policy = Arc::new(cfg.target_policy.clone());

    // v0.2.0 S3: initialize bundle endpoint context if enabled. Load
    // persistent token store from configured path. Store is wrapped в
    // `Mutex` so per-connection handlers can redeem/save safely.
    let bundle_ctx = if cfg.bundle_endpoint.enabled {
        match bundle_tokens::BundleTokenStore::load(&cfg.bundle_endpoint.token_store_path) {
            Ok(store) => {
                operational_log::info_bundle_enabled(
                    cfg.logging.policy(),
                    &cfg.bundle_endpoint.token_store_path,
                    &cfg.bundle_endpoint.path_prefix,
                    store.len(),
                );
                Some(Arc::new(
                    session::bundle_endpoint::BundleEndpointContext::new(
                        cfg.bundle_endpoint.clone(),
                        store,
                        cfg.logging.policy(),
                    ),
                ))
            }
            Err(err) => {
                operational_log::error_failure(
                    cfg.logging.policy(),
                    operational_log::FailureStage::ConnectionAdmission,
                    operational_log::FailureReason::RequestFailed,
                    None,
                    &err,
                );
                None
            }
        }
    } else {
        None
    };

    // Connection limiter
    let max_conn = connection_permit_limit(cfg.limits.max_connections);
    let semaphore = Arc::new(Semaphore::new(max_conn));
    let socket_admission = session::admission::SocketAdmissionLimiter::new(
        cfg.limits.max_unauthenticated_connections_per_ip,
    );

    // Rate limiter
    let rate_limiter = RateLimiter::new(
        cfg.rate_limit.max_auth_failures_per_ip,
        cfg.rate_limit.ban_duration_secs,
        cfg.rate_limit.enabled,
    )
    .with_operational_log(cfg.logging.policy())
    .with_trusted_proxies(
        &cfg.rate_limit.trusted_proxy_cidrs,
        &cfg.rate_limit.forwarded_ip_header,
    )?;

    // Background cleanup for rate limiter (every 60s)
    let rl_cleanup = rate_limiter.clone();
    let _cleanup_task = OwnedTask(tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            rl_cleanup.cleanup().await;
        }
    }));

    // QUIC/H3 ingress lives on UDP and can share the same host:port.
    // Wait for QUIC bind to complete before signalling overall ready,
    // so tests/clients don't race the QUIC endpoint construction.
    let mut quic_cfg = cfg.clone();
    // With listen port zero, both default listeners must use the actual TCP
    // address. Binding UDP to the original :0 would choose a different port
    // even though readiness reports one shared TCP/QUIC address. An explicit
    // transport.quic_listen still overrides this default in the QUIC server.
    quic_cfg.listen = bound_address.to_string();
    let quic_rate_limiter = rate_limiter.clone();
    let quic_semaphore = semaphore.clone();
    let (quic_ready_tx, quic_ready_rx) = tokio::sync::oneshot::channel();
    let (quic_shutdown_tx, quic_shutdown_rx) = tokio::sync::oneshot::channel();
    // Keep the endpoint's task owner outside quic_task: an outer grace timeout
    // must still be able to join H3 workers and Quinn's UDP-owning drivers.
    let mut quic_runtime_tasks = session::quic::QuicRuntimeTasks::new(cfg.logging.policy());
    let quic_runtime = quic_runtime_tasks.runtime();
    let quic_sessions = quic_runtime_tasks.sessions();
    // Share the already verified keyring and registry watcher with QUIC.
    // Never reopen registry authorization after the TCP startup read.
    let quic_auth = auth.clone();
    // Exclusive HTTPS bridge and CDN-fronted origins have no UDP ingress: a
    // CDN does not carry QUIC to the origin, and an open UDP listener would
    // only make the origin discoverable.
    let bridge_only =
        cfg.transport.https_bridge.is_some() || cfg.transport.fronted_origin.is_some();
    let mut quic_task = OwnedTask(tokio::spawn(async move {
        if bridge_only {
            // Dropping the ready sender reports no UDP ingress. No QUIC
            // endpoint is constructed in exclusive HTTPS bridge mode.
            return Ok(());
        }
        session::quic::run_quic_server_with_ready_and_controls(
            session::quic::VerifiedQuicStartup {
                cfg: quic_cfg,
                auth: quic_auth,
            },
            Some(session::quic::QuicReadiness::Report(quic_ready_tx)),
            quic_rate_limiter,
            quic_semaphore,
            Some(quic_shutdown_rx),
            quic_runtime,
            quic_sessions,
        )
        .await
    }));
    let (quic_bound, quic_failure) = match quic_ready_rx.await {
        Ok(Ok(())) => (true, None),
        Ok(Err(failure)) => (false, Some(failure)),
        Err(_) => (false, Some(session::quic::QuicStartupFailure::unreported())),
    };
    anyhow::ensure!(
        quic_bound || !cfg.transport.quic_required,
        "required QUIC ingress failed before readiness: {}",
        quic_failure.expect("failed readiness has a static report")
    );
    if !quic_bound && !bridge_only {
        operational_log::warn_optional_quic_unavailable(
            cfg.logging.policy(),
            &quic_failure.expect("failed readiness has a static report"),
        );
    }
    let mut policy_status = device_policy_status::StatusServer::start(
        cfg.transport.device_policy_status_socket.as_deref(),
        auth.inner_tls.as_ref(),
    )
    .context("start private device policy status")?;
    let policy_status_enabled = policy_status.enabled();
    tracing::info!(
        event_code = "server_ingress_ready",
        tcp_listener_bound = true,
        quic_listener_bound = quic_bound,
        quic_required = cfg.transport.quic_required,
        "required server listeners are ready; application reachability is not yet verified"
    );
    match ready {
        Some(Readiness::Unit(tx)) => {
            let _ = tx.send(());
        }
        Some(Readiness::Address(tx)) => {
            let _ = tx.send(bound_address);
        }
        None => {}
    }

    let mut sessions = tokio::task::JoinSet::new();
    let mut h2_request_owner = lifecycle::TaskGroupRegistryOwner::new(cfg.logging.policy());
    let h2_requests = h2_request_owner.registry();
    let mut quic_finished = false;
    let mut quic_finished_successfully = false;
    // Task ownership also closes every session on cancellation or early error.
    let server_result: anyhow::Result<()> = loop {
        tokio::select! {
            _ = policy_status.stopped(), if policy_status_enabled => {
                break Err(anyhow::anyhow!("configured private policy status listener stopped"));
            }
            accept_result = listener.accept() => {
                let (sock, peer) = match accept_result {
                    Ok(accepted) => accepted,
                    Err(error) => break Err(error.into()),
                };
                phase_witness::note(witness.as_ref(), phase_witness::ServerPhase::TcpAccepted);
                let admission = session::AdmissionBudget::new(std::time::Duration::from_millis(limits.read_timeout_ms));
                if !matches!(tokio::time::timeout_at(admission.deadline, rate_limiter.is_socket_banned(peer)).await, Ok(false)) { continue; }
                // Kernel socket identity only. Proxy-origin sockets share this
                // quota until device/token proof supplies an authorized lease.
                let Some(socket_permit) = socket_admission.try_acquire(peer.ip()) else { continue; };
                let admission = admission.with_socket_permit(socket_permit);

                // Acquire connection permit
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        operational_log::warn_counted(
                            cfg.logging.policy(),
                            operational_log::FailureStage::ConnectionAdmission,
                            operational_log::FailureReason::Capacity,
                            Some(peer),
                            max_conn,
                            &peer,
                        );
                        drop(sock);
                        continue;
                    }
                };

                let acceptor = acceptor.clone();
                let auth = auth.clone();
                let fallback = fallback.clone();
                let limits = limits.clone();
                let transport = transport.clone();
                let target_policy = target_policy.clone();
                let rate_limiter = rate_limiter.clone();
                let bundle_ctx = bundle_ctx.clone();
                let h2_requests = h2_requests.clone();
                let witness = witness.clone();

                sessions.spawn(async move {
                    let _phase_owner = phase_witness::SessionPhaseOwner::new(witness.as_ref());
                    let mut sock = sock;
                    let _permit = permit; // held until task completes
                    // Bound the TLS handshake. The permit is taken BEFORE the
                    // handshake and held for the whole task, so without this a peer
                    // that opens TCP and sends a partial ClientHello (or nothing)
                    // pins a permit forever: max_connections cheap sockets and the
                    // listener is dead, with no authentication and nothing for the
                    // auth-failure rate limiter to count.
                    // Plain HTTP on the TLS port answers like a fronted
                    // origin, not like a bare TLS server.
                    //
                    // Without this, rustls rejects the non-TLS bytes with a
                    // 6-byte decode_error alert before any AEGIS code runs,
                    // while a Cloudflare-fronted origin returns an HTTP 400
                    // page. That was one of five probes distinguishing the
                    // relay from a fronted control.
                    //
                    // A TLS handshake record starts with 0x16. Peek does not
                    // consume, so a real ClientHello proceeds untouched.
                    let mut first = [0u8; 1];
                    match tokio::time::timeout_at(
                        admission.deadline,
                        sock.peek(&mut first),
                    )
                    .await
                    {
                        Ok(Ok(1)) if first[0] != 0x16 => {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            let body = session::decoy::plain_http_on_tls_port();
                            // Drain the request first. Closing with unread bytes
                            // still in the receive buffer makes the kernel send
                            // RST instead of FIN, and the peer sees a connection
                            // reset rather than our response — which is a louder
                            // tell than the alert we are replacing.
                            let _ = tokio::time::timeout_at(admission.deadline, async {
                                let mut scratch = [0u8; 2048];
                                let _ = tokio::time::timeout(
                                    std::time::Duration::from_millis(200),
                                    sock.read(&mut scratch),
                                ).await;
                                let _ = sock.write_all(body.as_bytes()).await;
                                let _ = sock.flush().await;
                                let _ = sock.shutdown().await;
                            }).await;
                            tracing::debug!(event_code = "plain_http_decoy_served", "plain http on tls port; served fronted-origin decoy");
                            return;
                        }
                        Ok(Ok(_)) => {}
                        Ok(Err(_)) | Err(_) => return,
                    }

                    if let Some(witness) = witness.as_ref() {
                        // Start below TLS only after the original peek/decoy path.
                        // The session task and permit still own the original socket.
                        let sock = witness.observe_wire_io(sock);
                        let handshake = tokio::time::timeout_at(
                            admission.deadline,
                            acceptor.accept(sock),
                        )
                        .await;
                        let handshake = match handshake {
                            Ok(result) => result,
                            Err(_) => {
                                tracing::debug!(event_code = "tls_handshake_timeout", "tls handshake timed out; dropping connection");
                                return;
                            }
                        };
                        match handshake {
                            Ok(tls) => {
                                phase_witness::note(Some(witness), phase_witness::ServerPhase::OuterTlsAccepted);
                                if let Err(e) = session::handle_tls_session(
                                    tls,
                                    &auth,
                                    &fallback,
                                    &limits,
                                    &transport,
                                    &target_policy,
                                    &rate_limiter,
                                    peer,
                                    bundle_ctx.as_deref(),
                                    &h2_requests,
                                    Some(witness),
                                    admission,
                                )
                                .await
                                {
                                    if session::benign_io_close(&e) {
                                        tracing::debug!(event_code = "tcp_session_closed_benignly", "session closed benignly");
                                    } else {
                                        operational_log::error_failure(
                                            auth.operational_log(),
                                            operational_log::FailureStage::TcpSession,
                                            operational_log::FailureReason::ConnectionFailed,
                                            Some(peer),
                                            &e,
                                        );
                                    }
                                }
                            }
                            Err(e) => operational_log::error_failure(
                                auth.operational_log(),
                                operational_log::FailureStage::TlsHandshake,
                                operational_log::FailureReason::HandshakeFailed,
                                Some(peer),
                                &e,
                            ),
                        }
                    } else {
                        let handshake = tokio::time::timeout_at(
                            admission.deadline,
                            acceptor.accept(sock),
                        )
                        .await;
                        let handshake = match handshake {
                            Ok(result) => result,
                            Err(_) => {
                                tracing::debug!(event_code = "tls_handshake_timeout", "tls handshake timed out; dropping connection");
                                return;
                            }
                        };
                        match handshake {
                            Ok(tls) => {
                                phase_witness::note(witness.as_ref(), phase_witness::ServerPhase::OuterTlsAccepted);
                                if let Err(e) = session::handle_tls_session(
                                    tls,
                                    &auth,
                                    &fallback,
                                    &limits,
                                    &transport,
                                    &target_policy,
                                    &rate_limiter,
                                    peer,
                                    bundle_ctx.as_deref(),
                                    &h2_requests,
                                    witness.as_ref(),
                                    admission,
                                )
                                .await
                                {
                                    if session::benign_io_close(&e) {
                                        tracing::debug!(event_code = "tcp_session_closed_benignly", "session closed benignly");
                                    } else {
                                        operational_log::error_failure(
                                            auth.operational_log(),
                                            operational_log::FailureStage::TcpSession,
                                            operational_log::FailureReason::ConnectionFailed,
                                            Some(peer),
                                            &e,
                                        );
                                    }
                                }
                            }
                            Err(e) => operational_log::error_failure(
                                auth.operational_log(),
                                operational_log::FailureStage::TlsHandshake,
                                operational_log::FailureReason::HandshakeFailed,
                                Some(peer),
                                &e,
                            ),
                        }
                    }
                });
            }
            result = sessions.join_next(), if !sessions.is_empty() => {
                if let Some(Err(error)) = result {
                    operational_log::warn_failure(
                        cfg.logging.policy(),
                        operational_log::FailureStage::TcpSessionTask,
                        operational_log::FailureReason::TaskFailed,
                        None,
                        &error,
                    );
                }
            }
            result = &mut quic_task.0, if !quic_finished => {
                quic_finished = true;
                quic_finished_successfully = matches!(&result, Ok(Ok(())));
                if cfg.transport.quic_required {
                    break Err(anyhow::anyhow!("required QUIC ingress stopped unexpectedly: {result:?}"));
                }
                if !bridge_only {
                    tracing::warn!(event_code = "server_optional_quic_stopped", "optional QUIC stopped; TCP remains available");
                }
            }
            result = &mut stop => {
                tracing::info!(clean_stop = result.is_ok(), "server stop requested, draining connections...");
                // Drop listener to stop accepting new connections.
                // Existing tasks will finish via their owned permit.
                break result;
            }
        }
    };

    drop(listener);

    // Stop accepting UDP/QUIC before draining the shared permit pool. Without
    // this, new H3 connections can race the graceful-shutdown wait forever.
    let _ = quic_shutdown_tx.send(());

    // A runtime failure is an immediate cancellation boundary, not a second
    // graceful interval. Preserve its original error after every child joins.
    let grace = if server_result.is_err() {
        std::time::Duration::ZERO
    } else {
        std::time::Duration::from_millis(cfg.limits.shutdown_grace_ms)
    };
    let registry_cutoff = tokio::time::Instant::now() + grace;
    let (tcp_drained, (quic_joined, quic_successful), registry_cleanup) = tokio::join!(
        drain_tasks(&mut sessions, grace, cfg.logging.policy()),
        async {
            if quic_finished {
                return (true, quic_finished_successfully);
            }
            // A second timeout bounds even unexpected QUIC task shutdown bugs.
            match tokio::time::timeout(grace, &mut quic_task.0).await {
                Ok(result) => {
                    let successful = matches!(&result, Ok(Ok(())));
                    if !successful {
                        operational_log::warn_quic_shutdown_result(cfg.logging.policy(), &result);
                    }
                    (true, successful)
                }
                Err(_) => (false, false),
            }
        },
        async {
            match device_registry_watcher.as_mut() {
                Some(watcher) => watcher.stop_and_join_read_until(registry_cutoff).await,
                None => Ok(()),
            }
        }
    );
    if !quic_joined {
        quic_task.0.abort();
        let _ = (&mut quic_task.0).await;
    }
    // TCP parent cancellation must not let its H2 children outlive this API.
    // Their per-connection groups remain joinable after the parents are gone.
    h2_request_owner.shutdown().await;
    quic_runtime_tasks.shutdown().await;
    tracing::info!(
        tcp_drained,
        quic_joined_within_grace = quic_joined,
        quic_stopped_successfully = quic_successful,
        "server stopped; remaining sessions cancelled after bounded grace"
    );

    if registry_cleanup.is_err() {
        // Static diagnostic only. Preserve a preceding runtime failure, while
        // never reporting successful shutdown with an unconfirmed read.
        tracing::warn!("registry watcher cleanup unconfirmed");
    }
    server_result.and(registry_cleanup.map_err(Into::into))
}

#[cfg(test)]
mod runtime_error_tests;

#[cfg(test)]
mod quic_startup_tests;

#[cfg(test)]
mod tests {
    use super::connection_permit_limit;

    #[cfg(unix)]
    #[tokio::test(flavor = "current_thread")]
    async fn startup_registry_wait_keeps_executor_responsive_and_never_reports_unverified_ready() {
        use aegis_core::secure_channel::{
            registry::{publish_snapshot, DeviceRegistry, RegistryTransaction},
            ServerSettings,
        };
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        publish_snapshot(
            &path,
            &DeviceRegistry::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                900,
            )
            .unwrap(),
        )
        .unwrap();
        let transaction = RegistryTransaction::begin(&path).unwrap();
        let cfg = crate::config::ServerConfig {
            listen: "127.0.0.1:0".into(),
            cert: dir.path().join("outer-absent.pem"),
            key: dir.path().join("outer-absent.key"),
            auth_token: String::new(),
            legacy_auth_tokens: Vec::new(),
            process_alias: None,
            logging: Default::default(),
            fallback: "close".into(),
            limits: Default::default(),
            rate_limit: Default::default(),
            target_policy: Default::default(),
            transport: crate::config::TransportConfig {
                inner_tls: Some(ServerSettings {
                    cert: dir.path().join("inner-absent.pem"),
                    key: dir.path().join("inner-absent.key"),
                    client_ca: dir.path().join("ca-absent.pem"),
                    device_registry: Some(path),
                    allowed_client_sha256: Vec::new(),
                    admission: Default::default(),
                    handshake_timeout_ms: 1000,
                    idle_timeout_ms: 1000,
                }),
                ..Default::default()
            },
            bundle_endpoint: Default::default(),
        };
        let (ready_send, mut ready_recv) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(super::run_server_with_shutdown(
            cfg,
            Some(ready_send),
            std::future::pending(),
        ));
        tokio::time::timeout(
            Duration::from_millis(500),
            tokio::time::sleep(Duration::from_millis(70)),
        )
        .await
        .unwrap();
        assert!(
            !task.is_finished(),
            "real lock still prevents verified startup"
        );
        assert!(matches!(
            ready_recv.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        drop(transaction);
        let error = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
        assert!(
            ready_recv.await.is_err(),
            "missing credential never reports ready"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn prepared_quic_consumes_verified_auth_without_reopening_locked_registry() {
        use aegis_core::secure_channel::registry::{
            publish_snapshot, DeviceRegistry, RegistryTransaction,
        };
        use std::time::{Duration, SystemTime, UNIX_EPOCH};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("registry.json");
        publish_snapshot(
            &path,
            &DeviceRegistry::new(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                900,
            )
            .unwrap(),
        )
        .unwrap();
        let identity = rcgen::generate_simple_self_signed(vec!["fixture.test".into()]).unwrap();
        let cert = dir.path().join("inner.pem");
        let key = dir.path().join("inner.key");
        std::fs::write(&cert, identity.cert.pem()).unwrap();
        std::fs::write(&key, identity.key_pair.serialize_pem()).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cfg: crate::config::ServerConfig = toml::from_str(&format!(
            r#"
listen = "127.0.0.1:0"
cert = "outer-credential-intentionally-missing.pem"
key = "outer-credential-intentionally-missing.key"
auth_token = ""
[transport.inner_tls]
cert = {cert:?}
key = {key:?}
client_ca = {cert:?}
device_registry = {path:?}
"#
        ))
        .unwrap();
        let auth = crate::session::TunnelAuthKeyring::from_config_for_startup(&cfg)
            .await
            .unwrap();
        let _transaction = RegistryTransaction::begin(&path).unwrap();
        let mut owners = crate::session::quic::QuicRuntimeTasks::new(Default::default());
        let (ready_send, ready_recv) = tokio::sync::oneshot::channel();
        let start = std::time::Instant::now();
        let result = crate::session::quic::run_quic_server_with_ready_and_controls(
            crate::session::quic::VerifiedQuicStartup {
                cfg,
                auth: auth.clone(),
            },
            Some(crate::session::quic::QuicReadiness::Unit(ready_send)),
            crate::rate_limit::RateLimiter::new(10, 1, false),
            std::sync::Arc::new(tokio::sync::Semaphore::new(1)),
            None,
            owners.runtime(),
            owners.sessions(),
        )
        .await;
        owners.shutdown().await;
        let error = result.unwrap_err();
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound,
            "prepared QUIC reaches credential validation without rereading locked registry"
        );
        assert!(start.elapsed() < Duration::from_millis(500));
        assert!(
            ready_recv.await.is_err(),
            "invalid outer credentials never bind/report endpoint ready"
        );
    }

    #[test]
    fn zero_or_oversized_connection_limit_maps_to_a_safe_semaphore_size() {
        let runtime_max = tokio::sync::Semaphore::MAX_PERMITS.min(u32::MAX as usize);
        assert_eq!(connection_permit_limit(0), runtime_max);
        assert_eq!(connection_permit_limit(usize::MAX), runtime_max);
        assert_eq!(connection_permit_limit(123), 123);
    }
}
