//! Same-port enrollment forwarding for a CDN-fronted origin ("variant B").
//!
//! Devices renew (and redeem) through the same public authority and port 443
//! as their tunnel. The relay never holds the issuer key or sees enrollment
//! plaintext: the enrollment TLS session runs end to end between the device
//! and the separate authority listener; this module only pipes the opaque
//! gRPC message bytes to that listener over a fresh, verified TLS/HTTP2
//! connection. The authority keeps its own issuer, challenges, proof checks,
//! one-request-per-connection model and idempotent receipt recovery.
use aegis_core::fronted_origin::EnrollmentForwardSettings;
use aegis_core::secure_channel::{self, enrollment_tls};
use anyhow::Context;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

/// Bounded above the authority's own 40-second connection deadline.
const FORWARD_TIMEOUT: Duration = Duration::from_secs(45);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// One enrollment exchange (TLS handshakes, CSR, receipt) is a few KiB.
/// The cap keeps the forwarder from becoming a generic unauthenticated pipe.
pub(crate) const MAX_FORWARD_BYTES: usize = 256 * 1024;

pub(crate) struct Forwarder {
    address: SocketAddr,
    server_name: rustls::pki_types::ServerName<'static>,
    authority: String,
    connector: tokio_rustls::TlsConnector,
    permits: Arc<Semaphore>,
}

impl Forwarder {
    pub(crate) fn load(settings: &EnrollmentForwardSettings) -> anyhow::Result<Self> {
        let roots = secure_channel::load_trust_roots(&settings.ca)
            .context("load enrollment authority outer CA")?;
        anyhow::ensure!(!roots.is_empty(), "enrollment authority outer CA is empty");
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        tls.resumption = rustls::client::Resumption::disabled();
        tls.enable_early_data = false;
        tls.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            address: settings.authority_address,
            server_name: rustls::pki_types::ServerName::try_from(settings.server_name.clone())
                .context("enrollment authority server name")?,
            authority: settings.server_name.clone(),
            connector: tokio_rustls::TlsConnector::from(Arc::new(tls)),
            permits: Arc::new(Semaphore::new(settings.max_concurrent)),
        })
    }

    /// Forward one gate-admitted enrollment stream. A missing permit or an
    /// unavailable authority is reported as an ordinary 503 before any body
    /// byte is accepted; the device retains its request and retries later.
    pub(crate) async fn forward(
        &self,
        request: http::Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
    ) -> anyhow::Result<()> {
        let Ok(_permit) = self.permits.clone().try_acquire_owned() else {
            unavailable(&mut respond);
            return Ok(());
        };
        tokio::time::timeout(
            FORWARD_TIMEOUT,
            self.forward_admitted(request, &mut respond),
        )
        .await
        .unwrap_or_else(|_| {
            respond.send_reset(h2::Reason::CANCEL);
            Err(anyhow::anyhow!("enrollment forward deadline exceeded"))
        })
    }

    async fn forward_admitted(
        &self,
        request: http::Request<h2::RecvStream>,
        respond: &mut h2::server::SendResponse<Bytes>,
    ) -> anyhow::Result<()> {
        let upstream = match self.open().await {
            Ok(upstream) => upstream,
            Err(error) => {
                unavailable(respond);
                return Err(error);
            }
        };
        let (mut sender, _driver) = upstream;
        let upstream_request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!(
                "https://{}{}",
                self.authority,
                enrollment_tls::GRPC_PATH
            ))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())?;
        let (response, upstream_send) = match sender.send_request(upstream_request, false) {
            Ok(pair) => pair,
            Err(error) => {
                unavailable(respond);
                return Err(error.into());
            }
        };
        let response = match tokio::time::timeout(CONNECT_TIMEOUT, response).await {
            Ok(Ok(response))
                if response.status() == http::StatusCode::OK
                    && response
                        .headers()
                        .get("content-type")
                        .is_some_and(|value| value == "application/grpc") =>
            {
                response
            }
            _ => {
                unavailable(respond);
                anyhow::bail!("enrollment authority did not accept the forwarded stream");
            }
        };
        let downstream = respond.send_response(
            http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())?,
            false,
        )?;
        let device_to_authority = pump(request.into_body(), upstream_send, false);
        let authority_to_device = pump(response.into_body(), downstream, true);
        tokio::try_join!(device_to_authority, authority_to_device)?;
        Ok(())
    }

    async fn open(
        &self,
    ) -> anyhow::Result<(
        h2::client::SendRequest<Bytes>,
        crate::lifecycle::OwnedTask<()>,
    )> {
        let tcp = tokio::time::timeout(
            CONNECT_TIMEOUT,
            tokio::net::TcpStream::connect(self.address),
        )
        .await
        .context("enrollment authority connect timed out")??;
        let tls = tokio::time::timeout(
            CONNECT_TIMEOUT,
            self.connector.connect(self.server_name.clone(), tcp),
        )
        .await
        .context("enrollment authority TLS timed out")??;
        anyhow::ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "enrollment authority requires HTTP/2"
        );
        let (sender, connection) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            h2::client::Builder::new()
                .initial_window_size(64 * 1024)
                .max_concurrent_streams(1)
                .handshake::<_, Bytes>(tls),
        )
        .await
        .context("enrollment authority HTTP/2 timed out")??;
        let driver = crate::lifecycle::OwnedTask(tokio::spawn(async move {
            let _ = connection.await;
        }));
        let sender = tokio::time::timeout(CONNECT_TIMEOUT, sender.ready())
            .await
            .context("enrollment authority stream not ready")??;
        Ok((sender, driver))
    }
}

fn unavailable(respond: &mut h2::server::SendResponse<Bytes>) {
    if let Ok(response) = http::Response::builder().status(503).body(()) {
        let _ = respond.send_response(response, true);
    }
}

/// Copy one direction under explicit flow control. Receive capacity is
/// released only after the destination accepted the bytes, so a stalled
/// peer back-pressures the other side instead of growing a buffer.
async fn pump(
    mut from: h2::RecvStream,
    mut to: h2::SendStream<Bytes>,
    grpc_trailers: bool,
) -> anyhow::Result<()> {
    let mut forwarded = 0usize;
    while let Some(chunk) = from.data().await {
        let mut chunk = chunk.context("enrollment forward body")?;
        let length = chunk.len();
        forwarded += length;
        if forwarded > MAX_FORWARD_BYTES {
            to.send_reset(h2::Reason::CANCEL);
            anyhow::bail!("enrollment forward exceeded its byte bound");
        }
        while !chunk.is_empty() {
            to.reserve_capacity(chunk.len());
            let capacity = std::future::poll_fn(|cx| to.poll_capacity(cx))
                .await
                .context("enrollment forward destination closed")??;
            if capacity == 0 {
                tokio::task::yield_now().await;
                continue;
            }
            let take = capacity.min(chunk.len());
            to.send_data(chunk.split_to(take), false)?;
        }
        from.flow_control().release_capacity(length)?;
    }
    let trailers = from
        .trailers()
        .await
        .context("enrollment forward trailers")?;
    match trailers {
        Some(trailers) => to.send_trailers(trailers)?,
        None if grpc_trailers => {
            let mut ok = http::HeaderMap::new();
            ok.insert("grpc-status", http::HeaderValue::from_static("0"));
            to.send_trailers(ok)?;
        }
        None => to.send_data(Bytes::new(), true)?,
    }
    Ok(())
}
