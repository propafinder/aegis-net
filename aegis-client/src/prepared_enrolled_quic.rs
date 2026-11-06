//! Held enrolled H3 carrier for a caller-owned, physically bound UDP socket.
//! This is outer transport only: the caller still owns inner device TLS,
//! PolicyAck, target authorization, packet leases and route selection.
use aegis_core::{carrier_program::SECURE_QUIC_AUTHORITY, secure_channel};
use anyhow::{ensure, Context};
use bytes::{Buf, Bytes};
use rustls::pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer};
use std::{
    fmt,
    future::Future,
    io,
    net::{SocketAddr, UdpSocket},
    pin::Pin,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::watch;

const MAX_HELD_PEM: usize = 1 << 20;

/// Only the Quinn handshake below may construct this marker. A timeout of the
/// enclosing H3 CONNECT/response budget is deliberately not this error.
#[derive(Debug, thiserror::Error)]
enum OuterHandshakeFailure {
    #[error("outer QUIC handshake deadline exhausted")]
    Deadline,
    #[error("outer QUIC handshake failed: {0}")]
    Connection(#[source] quinn::ConnectionError),
}

struct ScopeInner {
    _anchor: Arc<dyn Send + Sync>,
    closing: watch::Sender<bool>,
}

/// Exercise the scoped reactor cancellation primitive independently. The
/// enrolled endpoint uses EndpointShutdown so CLOSE can leave the socket
/// before this signal cancels the reactors.
#[cfg(test)]
struct ReactorOwner(Arc<ScopeInner>);
#[cfg(test)]
impl Drop for ReactorOwner {
    fn drop(&mut self) {
        self.0.closing.send_replace(true);
    }
}

/// A driver can be dropped before its first poll. Its already-running,
/// bounded supervisor owns the endpoint and the WorkGate/UDP anchor until
/// Quinn has had a chance to send CONNECTION_CLOSE, then cancels any
/// remaining scoped reactor. No caller task needs to poll to start cleanup.
struct EndpointShutdown {
    endpoint: quinn::Endpoint,
    signal: Option<tokio::sync::oneshot::Sender<()>>,
    _supervisor: tokio::task::JoinHandle<()>,
}
impl Drop for EndpointShutdown {
    fn drop(&mut self) {
        // Revoke the connection synchronously before any later task wakeup.
        // The supervisor owns its separate endpoint and scope clones until
        // bounded idle drain, so the WorkGate/UDP anchor cannot leave early.
        self.endpoint
            .close(quinn::VarInt::from_u32(0), b"held carrier closed");
        if let Some(sender) = self.signal.take() {
            let _ = sender.send(());
        }
    }
}

struct ScopedFuture {
    future: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    scope: Option<Arc<ScopeInner>>,
}
impl Drop for ScopedFuture {
    fn drop(&mut self) {
        drop(self.future.take());
        drop(self.scope.take());
    }
}

#[derive(Clone)]
struct ScopedRuntime(Arc<ScopeInner>);
impl fmt::Debug for ScopedRuntime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ScopedEnrolledQuicRuntime")
    }
}
impl ScopedRuntime {
    fn wrap(
        &self,
        future: Pin<Box<dyn Future<Output = ()> + Send>>,
    ) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        let mut task = ScopedFuture {
            future: Some(future),
            scope: Some(self.0.clone()),
        };
        Box::pin(async move {
            let mut closing = task.scope.as_ref().expect("scope held").closing.subscribe();
            if !*closing.borrow() {
                tokio::select! {
                    biased;
                    _ = closing.changed() => {},
                    () = task.future.as_mut().expect("future held").as_mut() => {},
                }
            }
            drop(closing);
            drop(task);
        })
    }
}
impl quinn::Runtime for ScopedRuntime {
    fn new_timer(&self, when: Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::Runtime::new_timer(&quinn::TokioRuntime, when)
    }
    fn spawn(&self, future: Pin<Box<dyn Future<Output = ()> + Send>>) {
        quinn::Runtime::spawn(&quinn::TokioRuntime, self.wrap(future));
    }
    fn wrap_udp_socket(&self, socket: UdpSocket) -> io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::Runtime::wrap_udp_socket(&quinn::TokioRuntime, socket)
    }
}

struct AbortH3(tokio::task::JoinHandle<()>);
impl Drop for AbortH3 {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// The complete H3 request and Quinn endpoint lifetime. The caller must poll
/// this future alongside the inner TLS stream and drop it on revocation.
pub type HeldQuicDriver = Pin<Box<dyn Future<Output = anyhow::Result<()>> + Send>>;

/// An authenticated outer H3 byte stream, not a device or packet grant.
#[must_use = "poll and retain the driver with the stream"]
pub struct HeldQuicConnection {
    stream: DuplexStream,
    driver: HeldQuicDriver,
}

impl HeldQuicConnection {
    pub fn into_parts(self) -> (DuplexStream, HeldQuicDriver) {
        (self.stream, self.driver)
    }
}

/// Parsed held identity and pinned outer trust. Raw PEM need not remain in
/// the provider after construction. This is neither a route nor an ACK grant.
pub struct PreparedQuicClient {
    crypto: rustls::ClientConfig,
}

impl PreparedQuicClient {
    /// Parse held bytes once, without opening any pathname or platform roots.
    /// The caller independently binds them to its signed profile and captured
    /// file generations before creating this value.
    pub fn from_held(
        outer_ca_pem: &[u8],
        device_cert_pem: &[u8],
        device_key_pem: &[u8],
    ) -> anyhow::Result<Self> {
        ensure!(
            !outer_ca_pem.is_empty()
                && outer_ca_pem.len() <= MAX_HELD_PEM
                && !device_cert_pem.is_empty()
                && device_cert_pem.len() <= MAX_HELD_PEM
                && !device_key_pem.is_empty()
                && device_key_pem.len() <= MAX_HELD_PEM,
            "held enrolled QUIC credential bounds"
        );
        let roots = secure_channel::trust_roots_from_pem(outer_ca_pem)?;
        let certs: Vec<_> =
            CertificateDer::pem_slice_iter(device_cert_pem).collect::<Result<_, _>>()?;
        ensure!(!certs.is_empty(), "held enrolled QUIC certificate absent");
        let key = PrivateKeyDer::from_pem_slice(device_key_pem)?;
        let mut crypto = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_client_auth_cert(certs, key)?;
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        crypto.resumption = rustls::client::Resumption::disabled();
        crypto.enable_early_data = false;
        crypto.key_log = Arc::new(rustls::NoKeyLog);
        Ok(Self { crypto })
    }

    fn fresh_tls_config(
        &self,
        authority: &crate::relay_endpoint_policy::RelayTransportAuthority,
    ) -> rustls::ClientConfig {
        let mut crypto = self.crypto.clone();
        // An IP SAN is a valid signed identity. Rustls must verify that IP
        // without sending an SNI extension; a DNS identity keeps SNI.
        crypto.enable_sni = authority.send_sni;
        crypto
    }

    fn fresh_config(
        &self,
        authority: &crate::relay_endpoint_policy::RelayTransportAuthority,
    ) -> anyhow::Result<quinn::ClientConfig> {
        // A new Quinn config has a fresh address-token store on each route
        // attempt. Rustls resumption and early data remain disabled above.
        let quic =
            quinn::crypto::rustls::QuicClientConfig::try_from(self.fresh_tls_config(authority))?;
        Ok(quinn::ClientConfig::new(Arc::new(quic)))
    }

    /// Open one exact enrolled H3 CONNECT on a caller-bound UDP socket. The
    /// caller must prove signed numeric peer/SNI, physical interface, exact
    /// UDP filter tuple, leak arm and held-source generation before entry.
    /// The lifetime anchor must own that UDP lease and an extra WorkGate permit.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        &self,
        peer: SocketAddr,
        tls_name: &str,
        socket: UdpSocket,
        timeout: Duration,
        lifetime_anchor: Arc<dyn Send + Sync>,
    ) -> anyhow::Result<HeldQuicConnection> {
        ensure!(
            peer.port() != 0
                && !peer.ip().is_unspecified()
                && !peer.ip().is_multicast()
                && !timeout.is_zero()
                && timeout <= Duration::from_secs(60),
            "held enrolled QUIC peer or deadline refused"
        );
        let authority =
            crate::relay_endpoint_policy::transport_authority_for_host(tls_name, "QUIC SNI")?;
        ensure!(
            authority.authority_host == tls_name,
            "held QUIC authority refused"
        );
        let local = socket.local_addr()?;
        ensure!(
            local.port() != 0
                && !local.ip().is_unspecified()
                && local.is_ipv4() == peer.is_ipv4()
                && socket
                    .peer_addr()
                    .is_err_and(|e| e.kind() == io::ErrorKind::NotConnected),
            "held QUIC socket is not physically bound"
        );
        socket.set_nonblocking(true)?;
        let config = self.fresh_config(&authority)?;
        let (closing, _) = watch::channel(false);
        let scope = ScopedRuntime(Arc::new(ScopeInner {
            _anchor: lifetime_anchor,
            closing,
        }));
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            Arc::new(scope.clone()),
        )?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let shutdown_endpoint = endpoint.clone();
        let shutdown_scope = scope.clone();
        let supervisor = tokio::spawn(async move {
            let _ = shutdown_rx.await;
            // Quinn's close queues an event. Keep its reactor and the anchor
            // alive until the endpoint goes idle, with a finite fail-closed
            // bound if the peer or local socket stops responding.
            let _ =
                tokio::time::timeout(Duration::from_secs(1), shutdown_endpoint.wait_idle()).await;
            shutdown_scope.0.closing.send_replace(true);
        });
        // The handle is owned until EndpointShutdown::drop signals cleanup.
        // There is no Arc/handle cycle: the bounded task owns only endpoint
        // and scope clones, which preserve the extra WorkGate permit.
        let shutdown = EndpointShutdown {
            endpoint: endpoint.clone(),
            signal: Some(shutdown_tx),
            _supervisor: supervisor,
        };
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::time::timeout_at(deadline, async move {
            let connecting = endpoint.connect_with(config, peer, tls_name)?;
            let conn = tokio::time::timeout_at(deadline, connecting)
                .await
                .map_err(|_| OuterHandshakeFailure::Deadline)?
                .map_err(OuterHandshakeFailure::Connection)?;
            let quic = h3_quinn::Connection::new(conn.clone());
            let mut builder = h3::client::builder();
            builder.enable_extended_connect(true);
            let (mut h3_owner, mut requests) = builder.build::<_, _, Bytes>(quic).await?;
            let h3_scope = scope.clone();
            let mut h3_driver = AbortH3(tokio::spawn(async move {
                h3_scope
                    .wrap(Box::pin(async move {
                        let _ = std::future::poll_fn(|cx| h3_owner.poll_close(cx)).await;
                    }))
                    .await;
            }));
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("https://{SECURE_QUIC_AUTHORITY}"))
                .body(())?;
            let mut stream = tokio::select! {
                sent = requests.send_request(request) => sent?,
                _ = &mut h3_driver.0 => anyhow::bail!("held H3 driver closed before CONNECT"),
            };
            let response = tokio::select! {
                received = stream.recv_response() => received?,
                _ = &mut h3_driver.0 => anyhow::bail!("held H3 driver closed before response"),
            };
            ensure!(
                response.status() == http::StatusCode::OK,
                "held enrolled QUIC carrier refused"
            );
            let (app, wire) = tokio::io::duplex(64 * 1024);
            let driver: HeldQuicDriver = Box::pin(async move {
                let _shutdown = shutdown;
                let _endpoint = endpoint;
                let _connection = conn;
                // h3 closes the connection when its last SendRequest drops.
                // Keep that sender through the full response body, including
                // downlink after the caller half-closes its uplink.
                let request_owner = requests;
                let (mut send, mut recv) = stream.split();
                let (mut local_read, mut local_write) = tokio::io::split(wire);
                let uplink = async {
                    let mut bytes = [0u8; 16 * 1024];
                    loop {
                        let n = local_read.read(&mut bytes).await?;
                        if n == 0 {
                            send.finish().await?;
                            break;
                        }
                        send.send_data(Bytes::copy_from_slice(&bytes[..n])).await?;
                    }
                    anyhow::Ok(())
                };
                let downlink = async {
                    while let Some(mut frame) = recv.recv_data().await? {
                        local_write
                            .write_all(&frame.copy_to_bytes(frame.remaining()))
                            .await?;
                    }
                    local_write.shutdown().await?;
                    anyhow::Ok(())
                };
                tokio::select! {
                    joined = async { tokio::try_join!(uplink, downlink) } => { joined?; },
                    _ = &mut h3_driver.0 => anyhow::bail!("held H3 driver closed during carrier"),
                }
                drop(request_owner);
                Ok(())
            });
            Ok(HeldQuicConnection {
                stream: app,
                driver,
            })
        })
        .await
        .context("held enrolled QUIC connect deadline exhausted")?
    }
}

/// Classify only an explicitly marked Quinn handshake failure. `Some(true)`
/// is a handshake timeout; `Some(false)` is a reset or version mismatch.
/// Unmarked I/O, the enclosing H3 deadline, authentication, registry and
/// inner TLS errors are never eligible for this fallback.
pub fn pre_auth_transport_failure(error: &anyhow::Error) -> Option<bool> {
    let marker = error
        .chain()
        .find_map(|cause| cause.downcast_ref::<OuterHandshakeFailure>())?;
    match marker {
        OuterHandshakeFailure::Deadline => Some(true),
        OuterHandshakeFailure::Connection(quinn::ConnectionError::TimedOut) => Some(true),
        OuterHandshakeFailure::Connection(
            quinn::ConnectionError::Reset | quinn::ConnectionError::VersionMismatch,
        ) => Some(false),
        OuterHandshakeFailure::Connection(_) => None,
    }
}

/// Convenience for a caller that already retains exact held PEM bytes. A
/// provider should usually keep `PreparedQuicClient` instead of raw key PEM.
#[allow(clippy::too_many_arguments)]
pub async fn connect_from_held(
    peer: SocketAddr,
    tls_name: &str,
    outer_ca_pem: &[u8],
    device_cert_pem: &[u8],
    device_key_pem: &[u8],
    socket: UdpSocket,
    timeout: Duration,
    lifetime_anchor: Arc<dyn Send + Sync>,
) -> anyhow::Result<HeldQuicConnection> {
    PreparedQuicClient::from_held(outer_ca_pem, device_cert_pem, device_key_pem)?
        .connect(peer, tls_name, socket, timeout, lifetime_anchor)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    struct DropFlag(Arc<AtomicBool>);
    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    fn held_quic_crypto_refuses_missing_or_changed_credentials_before_io() {
        let cert = rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
        let ca = cert.cert.pem();
        let key = cert.key_pair.serialize_pem();
        assert!(
            PreparedQuicClient::from_held(ca.as_bytes(), ca.as_bytes(), key.as_bytes()).is_ok()
        );
        assert!(PreparedQuicClient::from_held(b"", ca.as_bytes(), key.as_bytes()).is_err());
        assert!(PreparedQuicClient::from_held(b"not a CA", ca.as_bytes(), key.as_bytes()).is_err());
        assert!(
            PreparedQuicClient::from_held(ca.as_bytes(), b"not a cert", key.as_bytes()).is_err()
        );
        assert!(PreparedQuicClient::from_held(ca.as_bytes(), ca.as_bytes(), b"not a key").is_err());
        assert!(PreparedQuicClient::from_held(
            &vec![b'X'; MAX_HELD_PEM + 1],
            ca.as_bytes(),
            key.as_bytes()
        )
        .is_err());
    }

    #[test]
    fn held_quic_keeps_signed_dns_and_ip_identities_distinct() {
        let cert =
            rcgen::generate_simple_self_signed(vec!["relay.test".into(), "192.0.2.11".into()])
                .unwrap();
        let ca = cert.cert.pem();
        let key = cert.key_pair.serialize_pem();
        let prepared =
            PreparedQuicClient::from_held(ca.as_bytes(), ca.as_bytes(), key.as_bytes()).unwrap();
        for (name, send_sni) in [("relay.test", true), ("192.0.2.11", false)] {
            let authority =
                crate::relay_endpoint_policy::transport_authority_for_host(name, "QUIC SNI")
                    .unwrap();
            assert_eq!(authority.send_sni, send_sni);
            assert_eq!(prepared.fresh_tls_config(&authority).enable_sni, send_sni);
            assert!(prepared.fresh_config(&authority).is_ok());
        }
        assert!(crate::relay_endpoint_policy::transport_authority_for_host(
            "invalid TLS name with space",
            "QUIC SNI"
        )
        .is_err());
    }

    #[tokio::test]
    async fn scoped_reactor_cancels_and_keeps_filter_anchor_until_actual_drop() {
        let anchor_dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::new(AtomicBool::new(false));
        let anchor: Arc<dyn Send + Sync> = Arc::new(DropFlag(anchor_dropped.clone()));
        let (closing, _) = watch::channel(false);
        let scope = ScopedRuntime(Arc::new(ScopeInner {
            _anchor: anchor,
            closing,
        }));
        let owner = ReactorOwner(scope.0.clone());
        let marker = DropFlag(task_dropped.clone());
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        quinn::Runtime::spawn(
            &scope,
            Box::pin(async move {
                let _marker = marker;
                let _ = ready_tx.send(());
                std::future::pending::<()>().await;
            }),
        );
        ready_rx.await.unwrap();
        drop(owner);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !task_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!anchor_dropped.load(Ordering::SeqCst));
        drop(scope);
        assert!(anchor_dropped.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn held_quic_refuses_bad_peer_before_network_io() {
        let cert = rcgen::generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
        let ca = cert.cert.pem();
        let key = cert.key_pair.serialize_pem();
        let prepared =
            PreparedQuicClient::from_held(ca.as_bytes(), ca.as_bytes(), key.as_bytes()).unwrap();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let anchor: Arc<dyn Send + Sync> = Arc::new(());
        let bad_peer = prepared
            .connect(
                "127.0.0.1:0".parse().unwrap(),
                "relay.test",
                socket,
                Duration::from_secs(1),
                anchor.clone(),
            )
            .await
            .err()
            .unwrap();
        assert!(bad_peer.to_string().contains("peer or deadline refused"));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let bad_name = prepared
            .connect(
                "127.0.0.1:443".parse().unwrap(),
                "invalid TLS name with space",
                socket,
                Duration::from_secs(1),
                anchor,
            )
            .await
            .err()
            .unwrap();
        assert!(bad_name.to_string().contains("invalid QUIC SNI"));
    }

    #[tokio::test]
    async fn prefirst_poll_cancel_drops_reactor_without_running_it() {
        let anchor_dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::new(AtomicBool::new(false));
        let polled = Arc::new(AtomicBool::new(false));
        let anchor: Arc<dyn Send + Sync> = Arc::new(DropFlag(anchor_dropped.clone()));
        let (closing, _) = watch::channel(false);
        let scope = ScopedRuntime(Arc::new(ScopeInner {
            _anchor: anchor,
            closing,
        }));
        let owner = ReactorOwner(scope.0.clone());
        drop(owner);
        let marker = DropFlag(task_dropped.clone());
        let seen = polled.clone();
        quinn::Runtime::spawn(
            &scope,
            Box::pin(async move {
                let _marker = marker;
                seen.store(true, Ordering::SeqCst);
            }),
        );
        drop(scope);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !anchor_dropped.load(Ordering::SeqCst) || !task_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn delayed_reactor_destructor_retains_filter_anchor() {
        struct SlowDrop {
            started: Arc<AtomicBool>,
            finished: Arc<AtomicBool>,
            anchor_dropped: Arc<AtomicBool>,
        }
        impl Drop for SlowDrop {
            fn drop(&mut self) {
                self.started.store(true, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(80));
                assert!(!self.anchor_dropped.load(Ordering::SeqCst));
                self.finished.store(true, Ordering::SeqCst);
            }
        }
        let anchor_dropped = Arc::new(AtomicBool::new(false));
        let started = Arc::new(AtomicBool::new(false));
        let finished = Arc::new(AtomicBool::new(false));
        let anchor: Arc<dyn Send + Sync> = Arc::new(DropFlag(anchor_dropped.clone()));
        let (closing, _) = watch::channel(false);
        let scope = ScopedRuntime(Arc::new(ScopeInner {
            _anchor: anchor,
            closing,
        }));
        let owner = ReactorOwner(scope.0.clone());
        let marker = SlowDrop {
            started: started.clone(),
            finished: finished.clone(),
            anchor_dropped: anchor_dropped.clone(),
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        quinn::Runtime::spawn(
            &scope,
            Box::pin(async move {
                let _marker = marker;
                let _ = ready_tx.send(());
                std::future::pending::<()>().await;
            }),
        );
        ready_rx.await.unwrap();
        drop(owner);
        drop(scope);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(!anchor_dropped.load(Ordering::SeqCst));
        tokio::time::timeout(Duration::from_secs(1), async {
            while !finished.load(Ordering::SeqCst) || !anchor_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }

    #[test]
    fn preauth_classifier_has_exact_transport_allowlist() {
        assert_eq!(
            pre_auth_transport_failure(&anyhow::Error::new(OuterHandshakeFailure::Deadline)),
            Some(true)
        );
        assert_eq!(
            pre_auth_transport_failure(&anyhow::Error::new(OuterHandshakeFailure::Connection(
                quinn::ConnectionError::TimedOut
            ))),
            Some(true),
        );
        for error in [
            quinn::ConnectionError::Reset,
            quinn::ConnectionError::VersionMismatch,
        ] {
            assert_eq!(
                pre_auth_transport_failure(&anyhow::Error::new(OuterHandshakeFailure::Connection(
                    error
                ))),
                Some(false)
            );
        }
        assert_eq!(
            pre_auth_transport_failure(&anyhow::Error::new(quinn::ConnectionError::TimedOut)),
            None
        );
        assert_eq!(
            pre_auth_transport_failure(&anyhow::Error::new(OuterHandshakeFailure::Connection(
                quinn::ConnectionError::LocallyClosed
            ))),
            None
        );
        assert_eq!(
            pre_auth_transport_failure(&anyhow::Error::new(rustls::Error::General(
                "auth refused".into()
            ))),
            None
        );
        assert_eq!(
            pre_auth_transport_failure(&anyhow::Error::new(io::Error::from(
                io::ErrorKind::ConnectionRefused
            ))),
            None
        );
        assert_eq!(
            pre_auth_transport_failure(&anyhow::Error::new(io::Error::from(
                io::ErrorKind::TimedOut
            ))),
            None
        );
        assert_eq!(
            pre_auth_transport_failure(&anyhow::anyhow!("H3 application refused")),
            None
        );
    }

    #[tokio::test]
    async fn preauth_classifier_rejects_unmarked_h3_response_deadline() {
        let elapsed = tokio::time::timeout(Duration::from_millis(1), std::future::pending::<()>())
            .await
            .err()
            .unwrap();
        assert_eq!(pre_auth_transport_failure(&elapsed.into()), None);
    }
}

#[cfg(test)]
#[path = "prepared_enrolled_quic_live_tests.rs"]
mod live_tests;
