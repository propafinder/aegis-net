//! Bootstrap TLS is separate from device-authorized data-plane TLS. Completing
//! this handshake authenticates the authority only; issuance still requires an
//! invitation/current-device proof in the enrollment protocol. This module
//! cannot create a registry lease or open a traffic target.

use super::{certificates, invalid, key, load_trust_roots, provider};
use rustls::pki_types::ServerName;
use serde::Deserialize;
use std::io;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{Instant, Sleep};

pub const GRPC_PATH: &str = "/enrollment.v1.Authority/Exchange";
const ALPN: &[u8] = b"aegis-enroll/1";
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_SESSIONS: usize = 32;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientSettings {
    pub server_name: String,
    pub server_ca: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthoritySettings {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Clone)]
pub struct Client {
    config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
}

impl Client {
    pub fn load(settings: &ClientSettings) -> io::Result<Self> {
        let server_name = ServerName::try_from(settings.server_name.clone())
            .map_err(|_| invalid("invalid enrollment TLS server name"))?;
        let mut config = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("enrollment TLS 1.3 unavailable"))?
            .with_root_certificates(load_trust_roots(&settings.server_ca)?)
            .with_no_client_auth();
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        config.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            config: Arc::new(config),
            server_name,
        })
    }

    /// No invitation/CSR can be written through the returned stream until the
    /// pinned authority identity and the enrollment-only protocol are verified.
    pub async fn connect<S>(
        &self,
        carrier: S,
    ) -> io::Result<Session<tokio_rustls::client::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let stream = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            tokio_rustls::TlsConnector::from(self.config.clone())
                .connect(self.server_name.clone(), carrier),
        )
        .await
        .map_err(|_| timed_out())??;
        if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
            return Err(invalid("enrollment TLS protocol was not negotiated"));
        }
        Ok(Session::new(stream, None))
    }
}

#[derive(Clone)]
pub struct Authority {
    config: Arc<rustls::ServerConfig>,
    sessions: Arc<Semaphore>,
}

impl Authority {
    pub fn load(settings: &AuthoritySettings) -> io::Result<Self> {
        let mut config = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| invalid("enrollment TLS 1.3 unavailable"))?
            .with_no_client_auth()
            .with_single_cert(certificates(&settings.cert)?, key(&settings.key)?)
            .map_err(|_| invalid("invalid enrollment authority TLS identity"))?;
        config.alpn_protocols = vec![ALPN.to_vec()];
        config.send_tls13_tickets = 0;
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.max_early_data_size = 0;
        config.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self {
            config: Arc::new(config),
            sessions: Arc::new(Semaphore::new(MAX_SESSIONS)),
        })
    }

    /// The permit is acquired before TLS work and retained until the session
    /// is dropped. The service must also bound the whole handler by deadline()
    /// so a handler doing no I/O cannot retain capacity indefinitely.
    pub async fn accept<S>(
        &self,
        carrier: S,
    ) -> io::Result<Session<tokio_rustls::server::TlsStream<S>>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let permit = self.sessions.clone().try_acquire_owned().map_err(|_| {
            io::Error::new(
                io::ErrorKind::WouldBlock,
                "enrollment TLS capacity exhausted",
            )
        })?;
        let stream = tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            tokio_rustls::TlsAcceptor::from(self.config.clone()).accept(carrier),
        )
        .await
        .map_err(|_| timed_out())??;
        if stream.get_ref().1.alpn_protocol() != Some(ALPN) {
            return Err(invalid("enrollment TLS protocol was not negotiated"));
        }
        Ok(Session::new(stream, Some(permit)))
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "enrollment TLS deadline exceeded")
}

/// Every read and write has the same fixed deadline; activity cannot extend
/// the operation. There is no method to extract an unbounded inner stream.
pub struct Session<S> {
    stream: S,
    deadline: Pin<Box<Sleep>>,
    _permit: Option<OwnedSemaphorePermit>,
}

impl<S> Session<S> {
    fn new(stream: S, permit: Option<OwnedSemaphorePermit>) -> Self {
        Self {
            stream,
            deadline: Box::pin(tokio::time::sleep(SESSION_TIMEOUT)),
            _permit: permit,
        }
    }

    pub fn deadline(&self) -> Instant {
        self.deadline.deadline()
    }

    fn check_deadline(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        use std::future::Future;
        if self.deadline.as_mut().poll(cx).is_ready() {
            Err(timed_out())
        } else {
            Ok(())
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Session<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.check_deadline(cx)?;
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Session<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.check_deadline(cx)?;
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_deadline(cx)?;
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.check_deadline(cx)?;
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
#[path = "enrollment_tls_tests.rs"]
mod tests;
