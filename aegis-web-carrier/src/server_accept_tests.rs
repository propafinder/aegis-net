//! Actual owner-loop regressions using owned loopback TCP, verified TLS and h2.
use super::*;
use crate::{ClientSettings, KEY_HEADER};
use bytes::BytesMut;
use http::StatusCode;
use std::{path::PathBuf, sync::atomic::AtomicUsize};
use tokio::{net::TcpStream, sync::oneshot, time::timeout};
use tokio_rustls::TlsConnector;
use zeroize::Zeroizing;

const TEST_BOUND: Duration = Duration::from_secs(10);
const MARKER_BOUND: Duration = Duration::from_secs(1);
type AcceptedTcp = io::Result<(TcpStream, SocketAddr)>;

fn configs() -> (TlsAcceptor, Arc<rustls::ClientConfig>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let certified = rcgen::generate_simple_self_signed(vec!["site.test".into()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = rustls::pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der());
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key.into())
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let mut client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    client.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    (TlsAcceptor::from(Arc::new(server)), Arc::new(client))
}
// The only fault injection is at the accept source boundary. Children still
// execute the original TCP -> verified outer TLS -> h2 -> request -> OPEN path.
struct AcceptEvent {
    result: AcceptedTcp,
    delivered: Option<oneshot::Sender<()>>,
}
struct Fixture {
    server: Arc<Server>,
    listener: TcpListener,
    source: mpsc::Sender<AcceptEvent>,
    accepted: mpsc::Receiver<AcceptedSession>,
    connector: TlsConnector,
    stop: Cancellation,
    owner: Option<JoinHandle<(io::Result<()>, ServerStats)>>,
    results: Arc<AtomicUsize>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(owner) = &self.owner {
            owner.abort();
        }
    }
}
impl Fixture {
    async fn new() -> Self {
        let (acceptor, client) = configs();
        let limits = Limits::default();
        let credential = Credential::from_private_bytes(Zeroizing::new(vec![b'a'; 64])).unwrap();
        let server = Server::new(
            ServerSettings {
                client: ClientSettings {
                    authority: "site.test".into(),
                    descriptor_path: "/private/descriptor".into(),
                    credential_file: PathBuf::from(if cfg!(windows) {
                        "C:/fixture/private/key"
                    } else {
                        "/fixture/private/key"
                    }),
                },
                site_html: "<title>Owned fixture</title>".into(),
            },
            credential,
            limits.clone(),
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let ingress = listener.local_addr().unwrap();
        let (source, receiver) = mpsc::channel::<AcceptEvent>(8);
        let receiver = Arc::new(tokio::sync::Mutex::new(receiver));
        let (sender, accepted) = mpsc::channel(limits.max_sessions);
        let stop = Cancellation::default();
        let results = Arc::new(AtomicUsize::new(0));
        let owned_results = results.clone();
        let owned_server = server.clone();
        let owned_stop = stop.clone();
        let owner = tokio::spawn(async move {
            let result = owned_server
                .clone()
                .serve_with_accept(ingress, acceptor, sender, owned_stop, move || {
                    let receiver = receiver.clone();
                    let results = owned_results.clone();
                    async move {
                        let event = receiver.lock().await.recv().await;
                        match event {
                            Some(event) => {
                                results.fetch_add(1, Ordering::SeqCst);
                                if let Some(delivered) = event.delivered {
                                    let _ = delivered.send(());
                                }
                                event.result
                            }
                            None => Err(io::Error::new(
                                io::ErrorKind::BrokenPipe,
                                "test accept source closed",
                            )),
                        }
                    }
                })
                .await;
            // Capture immediately in this SAME task, with no yield or cleanup
            // polling that could hide the baseline's skipped abort/join.
            let returned_stats = owned_server.stats();
            (result, returned_stats)
        });
        Self {
            server,
            listener,
            source,
            accepted,
            connector: TlsConnector::from(client),
            stop,
            owner: Some(owner),
            results,
        }
    }
    async fn connect(&self) -> io::Result<Raw> {
        let address = self.listener.local_addr()?;
        let client = TcpStream::connect(address).await?;
        let accepted = self.listener.accept().await?;
        self.source
            .send(AcceptEvent {
                result: Ok(accepted),
                delivered: None,
            })
            .await
            .map_err(|_| crate::failed())?;
        let name = rustls::pki_types::ServerName::try_from("site.test").unwrap();
        let tls = self.connector.connect(name, client).await?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture missing h2",
            ));
        }
        let (send, connection) = h2::client::Builder::new()
            .handshake::<_, Bytes>(tls)
            .await
            .map_err(convert)?;
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Raw {
            send,
            driver: Some(driver),
            next: 0,
        })
    }
    async fn fault(&self, error: io::Error) {
        let (delivered, receipt) = oneshot::channel();
        self.source
            .send(AcceptEvent {
                result: Err(error),
                delivered: Some(delivered),
            })
            .await
            .unwrap();
        receipt.await.unwrap();
    }
    fn snapshot(&self, id: [u8; 32]) -> Option<Snapshot> {
        let sessions = self.server.sessions.lock().unwrap();
        sessions.get(&id).map(|session| Snapshot {
            owner: session.owner,
            opened: session.lifetime.opened,
            authentication: session.lifetime.state.load(Ordering::Acquire),
        })
    }
    async fn finish(&mut self) -> (io::Result<()>, ServerStats) {
        self.stop.cancel();
        let returned = timeout(TEST_BOUND, self.owner.take().unwrap())
            .await
            .unwrap()
            .unwrap();
        // This ensures failed-baseline fixtures clean their owned resources.
        // It does not replace the captured immediate-at-return assertion above.
        timeout(TEST_BOUND, async {
            loop {
                let stats = self.server.stats();
                if stats.active_connections == 0
                    && stats.active_sessions == 0
                    && stats.active_requests == 0
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        returned
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Snapshot {
    owner: u64,
    opened: Instant,
    authentication: u8,
}
struct Raw {
    send: h2::client::SendRequest<Bytes>,
    driver: Option<JoinHandle<()>>,
    next: u64,
}
impl Drop for Raw {
    fn drop(&mut self) {
        if let Some(driver) = &self.driver {
            driver.abort();
        }
    }
}
impl Raw {
    async fn exchange(
        &mut self,
        server: &Server,
        id: [u8; 32],
        flags: u8,
        bytes: &[u8],
    ) -> io::Result<Reply> {
        let descriptor = server.descriptor()?;
        let sequence = self.next;
        let body = Frame {
            id,
            sequence,
            ack: sequence.saturating_sub(1),
            flags,
            data: Bytes::copy_from_slice(bytes),
        }
        .encode();
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://site.test{}", descriptor.path))
            .header("content-type", "application/octet-stream")
            .header(KEY_HEADER, server.credential.header_value())
            .body(())
            .map_err(convert)?;
        self.send = self.send.clone().ready().await.map_err(convert)?;
        let (response, send) = self.send.send_request(request, false).map_err(convert)?;
        protocol::send(send, body).await?;
        let response = response.await.map_err(convert)?;
        if response.status() != StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture carrier refused",
            ));
        }
        let reply = Reply::decode(
            protocol::collect(
                response.into_body(),
                server.limits.frame_bytes + protocol::RESPONSE_HEADER,
            )
            .await?,
            server.limits.frame_bytes,
        )?;
        if reply.id != id || reply.sequence != sequence || reply.fin {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "fixture reply mismatch",
            ));
        }
        self.next += 1;
        Ok(reply)
    }
    async fn marker(
        &mut self,
        server: &Server,
        id: [u8; 32],
        application: &mut ApplicationStream,
        upload: &[u8],
        download: &[u8],
    ) -> io::Result<()> {
        timeout(MARKER_BOUND, async {
            let reply = self.exchange(server, id, 0, upload).await?;
            if !reply.data.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected prior output",
                ));
            }
            let mut received = vec![0; upload.len()];
            application.read_exact(&mut received).await?;
            if received != upload {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "upload marker mismatch",
                ));
            }
            application.write_all(download).await?;
            let mut output = BytesMut::new();
            for _ in 0..32 {
                let reply = self.exchange(server, id, 0, b"").await?;
                if output.len() + reply.data.len() > download.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "extra marker bytes",
                    ));
                }
                output.extend_from_slice(&reply.data);
                if output.len() == download.len() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            if output.as_ref() != download {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "download marker mismatch",
                ));
            }
            Ok(())
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "fixture marker timeout"))?
    }
    async fn finish(&mut self) {
        let driver = self.driver.take().unwrap();
        driver.abort();
        let _ = timeout(TEST_BOUND, driver).await.unwrap();
    }
}
async fn retained_session(error: io::Error) {
    timeout(TEST_BOUND, async {
        let mut fixture = Fixture::new().await;
        let mut raw = fixture.connect().await.unwrap();
        let id = [0x73; 32];
        raw.exchange(&fixture.server, id, OPEN, b"").await.unwrap();
        let (mut application, _authentication) =
            fixture.accepted.recv().await.unwrap().into_parts();
        raw.marker(
            &fixture.server,
            id,
            &mut application,
            b"before-upload",
            b"before-download",
        )
        .await
        .unwrap();
        let before = fixture.snapshot(id).unwrap();
        assert_eq!(before.authentication, 0); // No forged inner authorization.
        fixture.fault(error).await;
        let after_marker = raw
            .marker(
                &fixture.server,
                id,
                &mut application,
                b"after-upload",
                b"after-download",
            )
            .await;
        let after = fixture.snapshot(id);
        let new_connection = timeout(MARKER_BOUND, fixture.connect()).await;
        let mut new_raw = new_connection.ok().and_then(Result::ok);
        let new_open = if let Some(raw) = new_raw.as_mut() {
            raw.exchange(&fixture.server, [0x75; 32], OPEN, b"")
                .await
                .map(|_| ())
        } else {
            Err(crate::failed())
        };
        let still_serving = !fixture.owner.as_ref().unwrap().is_finished();
        let (result, returned_stats) = fixture.finish().await;
        raw.finish().await;
        if let Some(raw) = new_raw.as_mut() {
            raw.finish().await;
        }
        drop(application);
        // Assertions happen AFTER bounded owned cleanup, even on genuine RED.
        assert!(
            after_marker.is_ok(),
            "actual same-session exchange failed: {after_marker:?}"
        );
        assert!(
            new_open.is_ok(),
            "next real accepted TLS/h2 stream failed: {new_open:?}"
        );
        assert_eq!(
            after,
            Some(before),
            "session owner/opened/auth state changed"
        );
        assert!(
            still_serving,
            "transient accept error ended the actual owner loop"
        );
        result.unwrap();
        assert_eq!(returned_stats.active_connections, 0);
        assert_eq!(returned_stats.active_sessions, 0);
        assert_eq!(returned_stats.active_requests, 0);
    })
    .await
    .unwrap();
}
#[tokio::test]
async fn interrupted_accept_preserves_same_actual_tls_h2_session() {
    retained_session(io::Error::new(
        io::ErrorKind::Interrupted,
        "test interrupted accept",
    ))
    .await;
}
#[tokio::test]
async fn aborted_accept_preserves_same_actual_tls_h2_session() {
    retained_session(io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "test aborted accept",
    ))
    .await;
}
async fn fatal_accept(error: io::Error) {
    let expected_kind = error.kind();
    let expected_raw = error.raw_os_error();
    let expected_message = error.to_string();
    timeout(TEST_BOUND, async {
        let mut fixture = Fixture::new().await;
        let mut raw = fixture.connect().await.unwrap();
        let id = [0x74; 32];
        raw.exchange(&fixture.server, id, OPEN, b"").await.unwrap();
        let (mut application, _authentication) =
            fixture.accepted.recv().await.unwrap().into_parts();
        raw.marker(
            &fixture.server,
            id,
            &mut application,
            b"fatal-before-upload",
            b"fatal-before-download",
        )
        .await
        .unwrap();
        fixture.fault(error).await;
        let (result, returned_stats) = fixture.finish().await;
        raw.finish().await;
        drop(application);
        let error = result.expect_err("fatal accept error became healthy completion");
        assert_eq!(error.kind(), expected_kind);
        assert_eq!(error.raw_os_error(), expected_raw);
        assert_eq!(error.to_string(), expected_message);
        assert_eq!(
            returned_stats.active_connections, 0,
            "owner returned before its actual TLS child released connection custody"
        );
        assert_eq!(
            returned_stats.active_sessions, 0,
            "owner returned before actual ConnectionOwner removed the session"
        );
        assert_eq!(returned_stats.active_requests, 0);
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn would_block_accept_preserves_same_actual_tls_h2_session() {
    retained_session(io::Error::new(
        io::ErrorKind::WouldBlock,
        "test would-block accept",
    ))
    .await;
}
#[tokio::test]
async fn fatal_accept_returns_original_error_only_after_actual_child_cleanup() {
    fatal_accept(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "owned synthetic fatal accept",
    ))
    .await;
}
#[tokio::test]
async fn unknown_raw_accept_error_is_preserved_after_actual_child_cleanup() {
    // Synthetic unclassified errno, never a claim about an actual resource event.
    fatal_accept(io::Error::from_raw_os_error(999_999)).await;
}
#[tokio::test]
async fn cancellation_during_retry_joins_actual_live_child() {
    timeout(TEST_BOUND, async {
        let mut fixture = Fixture::new().await;
        let mut raw = fixture.connect().await.unwrap();
        let id = [0x76; 32];
        raw.exchange(&fixture.server, id, OPEN, b"").await.unwrap();
        let (mut application, _authentication) =
            fixture.accepted.recv().await.unwrap().into_parts();
        raw.marker(
            &fixture.server,
            id,
            &mut application,
            b"cancel-upload",
            b"cancel-download",
        )
        .await
        .unwrap();
        // Pause only after actual socket/marker setup; cancellation occurs at
        // this fixed Instant without a retry timer or preauth deadline advancing.
        tokio::time::pause();
        let at_fault = Instant::now();
        fixture
            .fault(io::Error::new(
                io::ErrorKind::Interrupted,
                "cancel fixture interrupted",
            ))
            .await;
        let (result, returned_stats) = fixture.finish().await;
        let cancel_elapsed = at_fault.elapsed();
        let closed = timeout(MARKER_BOUND, application.read_u8()).await;
        raw.finish().await;
        drop(application);
        result.unwrap();
        assert_eq!(
            cancel_elapsed,
            Duration::ZERO,
            "cancellation waited for retry deadline"
        );
        assert!(
            matches!(closed, Ok(Err(_))),
            "cancelled actual application stream stayed live"
        );
        assert_eq!(returned_stats.active_connections, 0);
        assert_eq!(returned_stats.active_sessions, 0);
        assert_eq!(returned_stats.active_requests, 0);
    })
    .await
    .unwrap();
}
#[tokio::test(start_paused = true)]
async fn repeated_ready_transients_obey_absolute_backoff_despite_cleanup_ticks() {
    let mut fixture = Fixture::new().await;
    fixture
        .fault(io::Error::new(
            io::ErrorKind::Interrupted,
            "rate fixture first",
        ))
        .await;
    let mut queued = true;
    for _ in 0..2 {
        queued &= fixture
            .source
            .send(AcceptEvent {
                result: Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "rate fixture next",
                )),
                delivered: None,
            })
            .await
            .is_ok();
    }
    let mut observed = vec![fixture.results.load(Ordering::SeqCst)];
    for advance in [49, 1, 49, 1] {
        tokio::time::advance(Duration::from_millis(advance)).await;
        // Let the SAME owner process cleanup, retry and its accept result.
        for _ in 0..4 {
            tokio::task::yield_now().await;
        }
        observed.push(fixture.results.load(Ordering::SeqCst));
    }
    let still_serving = !fixture.owner.as_ref().unwrap().is_finished();
    let (result, returned_stats) = fixture.finish().await;
    assert!(
        queued,
        "baseline owner ended before another accept result could be queued"
    );
    assert_eq!(
        observed,
        vec![1, 1, 2, 2, 3],
        "completed accept results bypassed or renewed fixed50ms delay"
    );
    assert!(still_serving);
    result.unwrap();
    assert_eq!(returned_stats.active_connections, 0);
    assert_eq!(returned_stats.active_sessions, 0);
    assert_eq!(returned_stats.active_requests, 0);
}

// Native resource-error regressions inject only an actual accept result. They
// never exhaust descriptors, change process limits, or weaken inner admission.
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod resource_accept {
    use super::*;
    use aegis_core::secure_channel::{self, OpenRequest, Transport};
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair,
        KeyUsagePurpose,
    };

    #[cfg(windows)]
    const FILE_LIMIT_ERRNO: i32 = 10_024; // Winsock WSAEMFILE.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    const FILE_LIMIT_ERRNO: i32 = 24; // EMFILE, not an ErrorKind-only substitute.

    struct InnerIdentity {
        _directory: tempfile::TempDir,
        server: secure_channel::Server,
        allowed: secure_channel::Client,
    }
    fn inner_identity() -> InnerIdentity {
        let directory = tempfile::tempdir().unwrap();
        let private = directory.path().join("owned-inner");
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&private)
                .unwrap();
        }
        #[cfg(windows)]
        aegis_core::windows_file::create_private_directory(&private, false, false).unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let path = private.join(name);
            aegis_core::secret_file::write_private_new(&path, bytes).unwrap();
            path
        };
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let ca = params.self_signed(&ca_key).unwrap();
        let ca_path = write("ca.pem", ca.pem().as_bytes());
        let mut identities = Vec::new();
        for (name, usage) in [
            ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
            ("allowed.test", ExtendedKeyUsagePurpose::ClientAuth),
        ] {
            let mut params = CertificateParams::new(vec![name.into()]).unwrap();
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![usage];
            let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            let certificate = params.signed_by(&key, &ca, &ca_key).unwrap();
            let cert_path = write(&format!("{name}.pem"), certificate.pem().as_bytes());
            let key_path = write(&format!("{name}.key"), key.serialize_pem().as_bytes());
            let digest: [u8; 32] = Sha256::digest(certificate.der().as_ref()).into();
            identities.push((cert_path, key_path, digest));
        }
        let server = secure_channel::Server::load(&secure_channel::ServerSettings {
            admission: Default::default(),
            cert: identities[0].0.clone(),
            key: identities[0].1.clone(),
            client_ca: ca_path.clone(),
            allowed_client_sha256: vec![identities[1]
                .2
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()],
            device_registry: None,
            handshake_timeout_ms: 2000,
            idle_timeout_ms: 2000,
        })
        .unwrap();
        let allowed = secure_channel::Client::load(&secure_channel::ClientSettings {
            server_name: "inner.test".into(),
            server_ca: ca_path,
            cert: identities[1].0.clone(),
            key: identities[1].1.clone(),
        })
        .unwrap();
        InnerIdentity {
            _directory: directory,
            server,
            allowed,
        }
    }
    impl Fixture {
        async fn web_connection(&self) -> io::Result<crate::WebStream> {
            let descriptor = timeout(TEST_BOUND, async {
                loop {
                    if let Ok(descriptor) = self.server.descriptor() {
                        break descriptor;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|_| io::ErrorKind::TimedOut)?;
            let connecting = crate::Client::connect(
                self.connector.clone(),
                &self.server.settings.client,
                descriptor,
                self.server.credential.clone(),
                self.server.limits.clone(),
            );
            let forwarding = async {
                let accepted = self.listener.accept().await?;
                self.source
                    .send(AcceptEvent {
                        result: Ok(accepted),
                        delivered: None,
                    })
                    .await
                    .map_err(|_| crate::failed())
            };
            // Both connection setup futures remain owned by this bounded case.
            let (connected, forwarded) = tokio::join!(connecting, forwarding);
            forwarded?;
            connected
        }
        fn session_id(&self, authentication: &AuthenticationHandle) -> [u8; 32] {
            *self
                .server
                .sessions
                .lock()
                .unwrap()
                .iter()
                .find(|(_, session)| Arc::ptr_eq(&session.lifetime, &authentication.0))
                .expect("actual accepted session absent")
                .0
        }
    }

    #[tokio::test]
    async fn web_stream_terminal_watch_survives_transfer_and_cancel() {
        timeout(TEST_BOUND, async {
            let fixture = Fixture::new().await;
            let stream = fixture.web_connection().await.unwrap();
            let mut terminal = stream.terminal_watch();
            assert!(!*terminal.borrow());
            stream.cancel().await;
            let changed = terminal.changed().await;
            assert!(changed.is_err() || *terminal.borrow());
        })
        .await
        .unwrap();
    }
    async fn inner_marker(
        client: &mut tokio_rustls::client::TlsStream<crate::WebStream>,
        server: &mut tokio_rustls::server::TlsStream<ApplicationStream>,
        upload: &[u8],
        download: &[u8],
    ) -> io::Result<()> {
        timeout(MARKER_BOUND, async {
            let using = async {
                client.write_all(upload).await?;
                client.flush().await?;
                let mut bytes = vec![0; download.len()];
                client.read_exact(&mut bytes).await?;
                if bytes != download {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                Ok::<(), io::Error>(())
            };
            let serving = async {
                let mut bytes = vec![0; upload.len()];
                server.read_exact(&mut bytes).await?;
                if bytes != upload {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                server.write_all(download).await?;
                server.flush().await
            };
            let (used, served) = tokio::join!(using, serving);
            used?;
            served
        })
        .await
        .map_err(|_| io::ErrorKind::TimedOut)?
    }
    async fn retained_authorized_session(raw_errno: i32) {
        timeout(TEST_BOUND, async {
            let identity = inner_identity();
            let mut fixture = Fixture::new().await;
            let carrier = fixture.web_connection().await.unwrap();
            let (application, authentication) = fixture.accepted.recv().await.unwrap().into_parts();
            let id = fixture.session_id(&authentication);
            let _permit = identity.server.try_acquire().unwrap();
            let (client, accepted) = tokio::join!(
                identity.allowed.connect(carrier),
                identity.server.accept_with_lease(application),
            );
            let mut client = client.unwrap();
            let (mut server, _lease) = accepted.unwrap();
            assert_eq!(
                client.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                server.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            // This state change follows actual certificate/pin/lease admission.
            authentication.mark_authenticated().unwrap();
            let using = async {
                secure_channel::write_open(
                    &mut client,
                    &OpenRequest {
                        version: 1,
                        host: "owned-fixture.example".into(),
                        port: 8443,
                        transport: Transport::Tcp,
                    },
                )
                .await
                .unwrap();
                assert_eq!(client.read_u8().await.unwrap(), 0);
            };
            let serving = async {
                let request = secure_channel::read_open(&mut server).await.unwrap();
                assert_eq!(request.host, "owned-fixture.example");
                assert_eq!(request.port, 8443);
                assert_eq!(request.transport, Transport::Tcp);
                // No target socket is opened by this identity/owner regression.
                server.write_u8(0).await.unwrap();
                server.flush().await.unwrap();
            };
            tokio::join!(using, serving);
            inner_marker(
                &mut client,
                &mut server,
                b"resource-before-up",
                b"resource-before-down",
            )
            .await
            .unwrap();
            let before = fixture.snapshot(id).unwrap();
            assert_eq!(before.authentication, 1);
            fixture.fault(io::Error::from_raw_os_error(raw_errno)).await;
            let after_marker = inner_marker(
                &mut client,
                &mut server,
                b"resource-after-up",
                b"resource-after-down",
            )
            .await;
            let after = fixture.snapshot(id);
            let next = timeout(MARKER_BOUND, fixture.connect()).await;
            let mut next = next.ok().and_then(Result::ok);
            let next_open = if let Some(raw) = next.as_mut() {
                raw.exchange(&fixture.server, [0x91; 32], OPEN, b"")
                    .await
                    .map(|_| ())
            } else {
                Err(crate::failed())
            };
            let still_serving = !fixture.owner.as_ref().unwrap().is_finished();
            drop(client);
            drop(server);
            let (result, returned) = fixture.finish().await;
            if let Some(raw) = next.as_mut() {
                raw.finish().await;
            }
            // Do not let assertions bypass bounded baseline cleanup.
            assert!(
                after_marker.is_ok(),
                "authorized channel lost for native errno {raw_errno}: {after_marker:?}"
            );
            assert_eq!(
                after,
                Some(before),
                "actual authorized session owner/deadline changed"
            );
            assert!(
                next_open.is_ok(),
                "new actual TLS/h2 OPEN lost for errno {raw_errno}: {next_open:?}"
            );
            assert!(still_serving, "resource pressure ended actual owner");
            result.unwrap();
            assert_eq!(returned.active_connections, 0);
            assert_eq!(returned.active_sessions, 0);
            assert_eq!(returned.active_requests, 0);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn native_emfile_retains_actual_authorized_session_and_next_accept() {
        retained_authorized_session(FILE_LIMIT_ERRNO).await;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn native_enfile_retains_actual_authorized_session_and_next_accept() {
        retained_authorized_session(23).await;
    }
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn native_enomem_retains_actual_authorized_session_and_next_accept() {
        retained_authorized_session(12).await;
    }
    #[cfg(any(
        target_os = "macos",
        windows,
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    ))]
    #[tokio::test]
    async fn native_enobufs_retains_actual_authorized_session_and_next_accept() {
        #[cfg(target_os = "macos")]
        let code = 55;
        #[cfg(target_os = "linux")]
        let code = 105;
        #[cfg(windows)]
        let code = 10_055;
        retained_authorized_session(code).await;
    }
    // Keep the runtime's initial paused Instant through actual socket setup.
    // A ready task suppresses Tokio's automatic time jumps while IO is pending;
    // its wall-clock bound releases that hold even if setup cannot complete.
    struct PausedSetup(Option<JoinHandle<()>>);
    impl PausedSetup {
        fn new() -> Self {
            Self(Some(tokio::spawn(async {
                let started = std::time::Instant::now();
                while started.elapsed() < TEST_BOUND {
                    tokio::task::yield_now().await;
                }
            })))
        }
        async fn finish(&mut self) {
            if let Some(task) = self.0.take() {
                task.abort();
                let _ = task.await;
            }
        }
    }
    impl Drop for PausedSetup {
        fn drop(&mut self) {
            if let Some(task) = &self.0 {
                task.abort();
            }
        }
    }
    #[tokio::test(start_paused = true)]
    async fn sustained_native_resource_errors_keep_absolute_backoff_and_cancel() {
        timeout(TEST_BOUND, async {
            let mut clock_hold = PausedSetup::new();
            let mut fixture = Fixture::new().await;
            let mut raw = fixture.connect().await.unwrap();
            raw.exchange(&fixture.server, [0x92; 32], OPEN, b"")
                .await
                .unwrap();
            let (application, _authentication) =
                fixture.accepted.recv().await.unwrap().into_parts();
            clock_hold.finish().await;
            fixture
                .fault(io::Error::from_raw_os_error(FILE_LIMIT_ERRNO))
                .await;
            let first = fixture.results.load(Ordering::SeqCst);
            let mut queued = true;
            for _ in 0..2 {
                queued &= fixture
                    .source
                    .send(AcceptEvent {
                        result: Err(io::Error::from_raw_os_error(FILE_LIMIT_ERRNO)),
                        delivered: None,
                    })
                    .await
                    .is_ok();
            }
            let mut observed = vec![fixture.results.load(Ordering::SeqCst)];
            for advance in [49, 1, 49, 1] {
                tokio::time::advance(Duration::from_millis(advance)).await;
                for _ in 0..4 {
                    tokio::task::yield_now().await;
                }
                observed.push(fixture.results.load(Ordering::SeqCst));
            }
            let at_cancel = Instant::now();
            let (result, returned) = fixture.finish().await;
            let cancelled_after = at_cancel.elapsed();
            raw.finish().await;
            drop(application);
            assert!(
                queued,
                "resource owner terminated before bounded errors queued"
            );
            assert_eq!(
                observed,
                vec![first, first, first + 1, first + 1, first + 2]
            );
            assert_eq!(
                cancelled_after,
                Duration::ZERO,
                "cancel waited for resource retry"
            );
            result.unwrap();
            assert_eq!(returned.active_connections, 0);
            assert_eq!(returned.active_sessions, 0);
            assert_eq!(returned.active_requests, 0);
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn resource_retry_does_not_renew_actual_anonymous_expiration() {
        timeout(TEST_BOUND, async {
            let mut fixture = Fixture::new().await;
            let mut raw = fixture.connect().await.unwrap();
            let id = [0x93; 32];
            raw.exchange(&fixture.server, id, OPEN, b"").await.unwrap();
            let (application, authentication) = fixture.accepted.recv().await.unwrap().into_parts();
            let before = fixture.snapshot(id).unwrap();
            assert_eq!(before.authentication, 0);
            tokio::time::pause();
            tokio::time::advance(Duration::from_secs(3)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            let before_fault = fixture.snapshot(id);
            fixture
                .fault(io::Error::from_raw_os_error(FILE_LIMIT_ERRNO))
                .await;
            let mut queued = true;
            for _ in 0..2 {
                queued &= fixture
                    .source
                    .send(AcceptEvent {
                        result: Err(io::Error::from_raw_os_error(FILE_LIMIT_ERRNO)),
                        delivered: None,
                    })
                    .await
                    .is_ok();
            }
            tokio::time::advance(Duration::from_millis(49)).await;
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            let during_retry = fixture.snapshot(id);
            tokio::time::advance(Duration::from_millis(2551)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
            let expired = fixture.snapshot(id).is_none();
            let late_authentication = authentication.mark_authenticated();
            let still_serving = !fixture.owner.as_ref().unwrap().is_finished();
            let (result, returned) = fixture.finish().await;
            raw.finish().await;
            drop(application);
            assert_eq!(
                before_fault,
                Some(Snapshot {
                    owner: before.owner,
                    opened: before.opened,
                    authentication: before.authentication,
                })
            );
            assert!(
                queued,
                "resource owner ended before sustained expiry control"
            );
            assert_eq!(
                during_retry,
                Some(before),
                "resource retry killed or renewed anonymous owner"
            );
            assert!(
                expired,
                "native resource retry extended original preauth deadline"
            );
            assert!(late_authentication.is_err());
            assert!(
                still_serving,
                "anonymous expiry/resource event ended listener"
            );
            result.unwrap();
            assert_eq!(returned.active_connections, 0);
            assert_eq!(returned.active_sessions, 0);
            assert_eq!(returned.active_requests, 0);
        })
        .await
        .unwrap();
    }
}
