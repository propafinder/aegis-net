//! Explicit authority-only listener. It does not construct relay auth, target
//! policies or traffic handlers. The issuer key belongs to this separate role.
use crate::enrollment_store::{CancellationOutcome, CancellationSelection, Issuer, IssuerConfig};
use aegis_core::h2_stream::H2Stream;
use aegis_core::secure_channel::{
    enrollment::protocol::ConnectionChallenge, enrollment_tls, enrollment_wire as wire,
    grpc_io::GrpcIo, registry,
};
use anyhow::{ensure, Context};
use clap::{Args, Subcommand};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

#[path = "enrollment_notify.rs"]
mod service_notify;

const MAX_CONNECTIONS: usize = 32;
const MAX_SIGNING_JOBS: usize = 8;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(40);

#[derive(Debug, Args)]
pub struct EnrollmentArgs {
    #[command(subcommand)]
    command: EnrollmentCommand,
}

#[derive(Debug, Subcommand)]
enum EnrollmentCommand {
    /// Run the explicitly configured enrollment authority, separate from relays.
    Serve {
        #[arg(long)]
        config: PathBuf,
    },
    /// Validate authority configuration and private state without a listener.
    Check {
        #[arg(long)]
        config: PathBuf,
    },
    /// Finish the exact retained issuance transaction locally, without signing.
    Recover {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityConfig {
    #[serde(default)]
    pub https_bridge: Option<aegis_core::https_bridge::ServerSettings>,
    pub listen: SocketAddr,
    pub outer_cert: PathBuf,
    pub outer_key: PathBuf,
    pub inner_tls: enrollment_tls::AuthoritySettings,
    pub issuer: IssuerConfig,
}

pub async fn run(args: EnrollmentArgs) -> anyhow::Result<()> {
    match args.command {
        EnrollmentCommand::Check { config } => {
            let config = load_config(&config)?;
            let _ = tokio::task::spawn_blocking(move || Prepared::new(&config))
                .await
                .context("authority startup validation worker failed")??;
            println!("enrollment authority configuration validated");
            Ok(())
        }
        EnrollmentCommand::Serve { config } => {
            let config = load_config(&config)?;
            let shutdown = crate::lifecycle::shutdown_signal()?;
            run_with_shutdown(config, None, shutdown).await
        }
        EnrollmentCommand::Recover { config } => {
            let config = load_config(&config)?;
            Issuer::open_recovery(&config.issuer)?.recover_pending()?;
            println!("retained issuance transaction recovered; distribution is not confirmed");
            Ok(())
        }
    }
}

fn load_config(path: &Path) -> anyhow::Result<AuthorityConfig> {
    Ok(load_config_with_digest(path)?.0)
}

fn load_config_with_digest(path: &Path) -> anyhow::Result<(AuthorityConfig, String)> {
    aegis_core::secret_file::trusted_read_parent(path)?;
    let bytes = aegis_core::secret_file::read_config(path, 64 * 1024)?;
    let config =
        toml::from_str(std::str::from_utf8(&bytes).context("invalid authority configuration")?)
            .map_err(|_| anyhow::anyhow!("invalid authority configuration"))?;
    Ok((config, hex::encode(Sha256::digest(&bytes))))
}

/// Explicit offline operator cancellation. Recovery-only construction checks
/// the public CA/journal; it never reads the private signing key or starts I/O.
pub(crate) fn cancel_enrollment(
    config: &Path,
    registry: &Path,
    device_id: &str,
    expected_certificate_sha256: Option<&str>,
) -> anyhow::Result<()> {
    let config = load_config(config)?;
    ensure!(
        config.issuer.registry == registry,
        "authority registry does not match cancellation target"
    );
    Issuer::open_cancellation(&config.issuer)?
        .cancel_enrollment(device_id, expected_certificate_sha256)?;
    Ok(())
}

/// Supported cancellation inspection: read-only, bounded and signing-key-free.
pub(crate) fn inspect_cancellation(
    config: &Path,
    registry: &Path,
    device_id: &str,
) -> anyhow::Result<CancellationSelection> {
    let (config, context) = load_config_with_digest(config)?;
    ensure!(
        config.issuer.registry == registry,
        "authority registry does not match cancellation target"
    );
    Ok(Issuer::open_cancellation(&config.issuer)?.inspect_cancellation(device_id, &context)?)
}

/// One exact selection CAS, rederived before writes under the exclusive lock.
pub(crate) fn cancel_selected_enrollment(
    config: &Path,
    registry: &Path,
    device_id: &str,
    expected_certificate_sha256: Option<&str>,
    selection_sha256: &str,
) -> anyhow::Result<CancellationOutcome> {
    let (config, context) = load_config_with_digest(config)?;
    ensure!(
        config.issuer.registry == registry,
        "authority registry does not match cancellation target"
    );
    Ok(
        Issuer::open_cancellation(&config.issuer)?.cancel_selected_enrollment(
            device_id,
            expected_certificate_sha256,
            selection_sha256,
            &context,
        )?,
    )
}

struct Prepared {
    bridge: Option<Arc<aegis_core::https_bridge::Gate>>,
    outer: tokio_rustls::TlsAcceptor,
    inner: enrollment_tls::Authority,
    issuer: Arc<Issuer>,
}

impl Prepared {
    fn new(config: &AuthorityConfig) -> anyhow::Result<Self> {
        if let Some(bridge) = &config.https_bridge {
            bridge.validate()?;
            ensure!(
                bridge.carrier.credential_file != config.outer_key
                    && bridge.carrier.credential_file != config.inner_tls.key
                    && bridge.carrier.credential_file != config.issuer.ca_key,
                "HTTPS bridge admission credential must be separate from authority keys"
            );
        }
        let bridge = config
            .https_bridge
            .as_ref()
            .map(aegis_core::https_bridge::Gate::load)
            .transpose()?
            .map(Arc::new);
        ensure!(
            config.listen.port() != 0,
            "authority requires an explicit nonzero port"
        );
        for path in [
            &config.outer_cert,
            &config.outer_key,
            &config.inner_tls.cert,
            &config.inner_tls.key,
        ] {
            ensure!(
                path.is_absolute(),
                "authority credential paths must be absolute"
            );
            aegis_core::secret_file::trusted_read_parent(path)?;
        }
        let cert = aegis_core::secret_file::read_config(&config.outer_cert, 1024 * 1024)?;
        let key = aegis_core::secret_file::read(&config.outer_key, 1024 * 1024)?;
        let certs = CertificateDer::pem_slice_iter(&cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| anyhow::anyhow!("invalid authority outer certificate"))?;
        let key = PrivateKeyDer::from_pem_slice(&key)
            .map_err(|_| anyhow::anyhow!("invalid authority outer key"))?;
        let mut outer = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
        outer.alpn_protocols = vec![b"h2".to_vec()];
        if bridge.is_some() {
            outer.alpn_protocols.push(b"http/1.1".to_vec());
        }
        outer.send_tls13_tickets = 0;
        outer.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        outer.max_early_data_size = 0;
        outer.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            bridge,
            outer: tokio_rustls::TlsAcceptor::from(Arc::new(outer)),
            inner: enrollment_tls::Authority::load(&config.inner_tls)?,
            issuer: Arc::new(Issuer::open(&config.issuer)?),
        })
    }
}

/// A timed-out request can lose its response after durable issuance. Its job
/// retains its own capacity permit, and exact retry uses the issuer journal.
/// All launched jobs stay tracked and are joined before listener shutdown ends.
struct SigningJobs {
    permits: Arc<Semaphore>,
    jobs: Mutex<Vec<JoinHandle<()>>>,
}

impl SigningJobs {
    fn new() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(MAX_SIGNING_JOBS)),
            jobs: Mutex::new(Vec::new()),
        }
    }

    async fn exchange(
        &self,
        issuer: Arc<Issuer>,
        request: wire::ExchangeRequest,
        mut challenge: ConnectionChallenge,
    ) -> wire::ExchangeResponse {
        let Ok(permit) = self.permits.clone().try_acquire_owned() else {
            return wire::ExchangeResponse::Failed {
                code: wire::FailureCode::Busy,
            };
        };
        let (tx, rx) = oneshot::channel();
        {
            let mut jobs = self.jobs.lock().unwrap_or_else(|e| e.into_inner());
            jobs.retain(|job| !job.is_finished());
            jobs.push(tokio::task::spawn_blocking(move || {
                let _permit = permit;
                let response = match issuer.exchange(&request, &mut challenge) {
                    Ok(receipt) => wire::ExchangeResponse::Issued {
                        receipt: Box::new(receipt),
                    },
                    // No arbitrary issuer error string reaches logs or the client.
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        wire::ExchangeResponse::Failed {
                            code: wire::FailureCode::Busy,
                        }
                    }
                    Err(_) => wire::ExchangeResponse::Failed {
                        code: wire::FailureCode::Rejected,
                    },
                };
                let _ = tx.send(response);
            }));
        }
        rx.await.unwrap_or(wire::ExchangeResponse::Failed {
            code: wire::FailureCode::Unavailable,
        })
    }

    async fn finish(&self) {
        let jobs = std::mem::take(&mut *self.jobs.lock().unwrap_or_else(|e| e.into_inner()));
        for job in jobs {
            let _ = job.await;
        }
    }
}

enum ConnectionEvent {
    Reaped,
    Accepted(std::io::Result<(tokio::net::TcpStream, SocketAddr)>),
}

async fn next_connection_event(
    listener: &tokio::net::TcpListener,
    connections: &mut JoinSet<()>,
) -> ConnectionEvent {
    tokio::select! {
        biased;
        // Completed tasks release permits but remain in JoinSet until reaped.
        // Drain them before a ready accept backlog can consume those permits.
        _ = connections.join_next(), if !connections.is_empty() => ConnectionEvent::Reaped,
        accepted = listener.accept() => ConnectionEvent::Accepted(accepted),
    }
}

pub async fn run_with_shutdown(
    config: AuthorityConfig,
    ready: Option<oneshot::Sender<SocketAddr>>,
    shutdown: impl std::future::Future<Output = ()>,
) -> anyhow::Result<()> {
    // Credential validation and the bounded registry publication wait precede
    // bind/notify/READY, without blocking the async authority executor.
    let prepare_config = config.clone();
    let prepared = tokio::task::spawn_blocking(move || Prepared::new(&prepare_config))
        .await
        .context("authority startup validation worker failed")??;
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    service_notify::notify()?;
    if let Some(ready) = ready {
        let _ = ready.send(listener.local_addr()?);
    }
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let signing = Arc::new(SigningJobs::new());
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    let result = loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break Ok(()),
            event = next_connection_event(&listener, &mut connections) => {
                let ConnectionEvent::Accepted(accepted) = event else { continue; };
                let (socket, _) = match accepted { Ok(value) => value, Err(error) => break Err(error.into()) };
                let Ok(permit) = permits.clone().try_acquire_owned() else { continue; };
                let outer = prepared.outer.clone();
                let inner = prepared.inner.clone();
                let issuer = prepared.issuer.clone();
                let signing = signing.clone();
                let bridge = prepared.bridge.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    let operation = async {
                        let mut stream = tokio::time::timeout(Duration::from_secs(5), outer.accept(socket)).await??;
                        if stream.get_ref().1.alpn_protocol() != Some(b"h2") {
                            if let Some(bridge) = &bridge {
                                return crate::session::https_bridge::serve_http1(&mut stream, bridge).await;
                            }
                        }
                        ensure!(stream.get_ref().1.alpn_protocol() == Some(b"h2"), "authority outer TLS requires HTTP/2");
                        serve_h2(stream, inner, issuer, signing, bridge).await
                    };
                    // Failures are intentionally not formatted with peer data,
                    // credentials or parser/issuer detail.
                    let _ = tokio::time::timeout(CONNECTION_TIMEOUT, operation).await;
                });
            }
        }
    };
    drop(listener);
    connections.shutdown().await;
    signing.finish().await;
    result
}

async fn serve_h2<S>(
    stream: S,
    inner: enrollment_tls::Authority,
    issuer: Arc<Issuer>,
    signing: Arc<SigningJobs>,
    bridge: Option<Arc<aegis_core::https_bridge::Gate>>,
) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(1)
        .max_header_list_size(8192)
        .initial_window_size(128 * 1024)
        .initial_connection_window_size(128 * 1024)
        .max_send_buffer_size(128 * 1024)
        .max_concurrent_reset_streams(2)
        .max_pending_accept_reset_streams(2)
        .max_local_error_reset_streams(Some(2));
    let mut connection =
        tokio::time::timeout(Duration::from_secs(5), builder.handshake(stream)).await??;
    let (request, mut respond) = tokio::time::timeout(Duration::from_secs(5), connection.accept())
        .await?
        .context("authority request missing")??;
    let valid = match &bridge {
        Some(gate) => gate.admits(&request, aegis_core::https_bridge::Purpose::Enrollment),
        None => valid_route(&request),
    };
    if !valid {
        if let Some(gate) = &bridge {
            let reply = crate::session::https_bridge::respond_h2(respond, gate.site(&request));
            tokio::pin!(reply);
            // This task also owns the H2 connection. Drive WINDOW_UPDATE and
            // queued frames while waiting for bounded public-response capacity.
            loop {
                tokio::select! {
                    result = &mut reply => { result?; break; }
                    additional = connection.accept() => match additional {
                        Some(Ok((_request, mut respond))) => respond.send_reset(h2::Reason::REFUSED_STREAM),
                        Some(Err(error)) => return Err(error.into()),
                        None => return Err(anyhow::anyhow!("HTTPS site carrier closed")),
                    }
                }
            }
        } else {
            respond.send_response(http::Response::builder().status(404).body(())?, true)?;
        }
        connection.graceful_shutdown();
        let _ = tokio::time::timeout(Duration::from_secs(1), async {
            while connection.accept().await.is_some() {}
        })
        .await;
        return Ok(());
    }
    let send = respond.send_response(
        http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())?,
        false,
    )?;
    let carrier = GrpcIo::new(H2Stream::new(send, request.into_body()));
    let operation = async {
        let mut session = inner.accept(carrier).await?;
        let deadline = session.deadline();
        tokio::time::timeout_at(deadline, async {
            let challenge = ConnectionChallenge::new(registry::unix_now()?)?;
            wire::write_challenge(&mut session, &challenge.message()).await?;
            let request = wire::read_request(&mut session).await?;
            let response = signing.exchange(issuer, request, challenge).await;
            wire::write_response(&mut session, &response).await?;
            session.shutdown().await?;
            std::io::Result::Ok(())
        })
        .await??;
        anyhow::Ok(())
    };
    tokio::pin!(operation);
    loop {
        tokio::select! {
            result = &mut operation => {
                result?;
                connection.graceful_shutdown();
                let _ = tokio::time::timeout(Duration::from_secs(1), async { while connection.accept().await.is_some() {} }).await;
                return Ok(());
            }
            additional = connection.accept() => match additional {
                Some(Ok((_request, mut respond))) => respond.send_reset(h2::Reason::REFUSED_STREAM),
                Some(Err(error)) => return Err(error.into()),
                None => return Ok(()),
            },
        }
    }
}

fn valid_route<T>(request: &http::Request<T>) -> bool {
    request.method() == http::Method::POST
        && request
            .uri()
            .path_and_query()
            .is_some_and(|path| path.as_str() == enrollment_tls::GRPC_PATH)
        && request
            .headers()
            .get("content-type")
            .is_some_and(|value| value == "application/grpc")
}

#[cfg(test)]
#[path = "enrollment_service_tests.rs"]
mod tests;
