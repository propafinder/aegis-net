//! Real loopback TCP + verified outer TLS + H2 requests, never a memory-only lab.
use aegis_web_carrier::{
    Cancellation, Client, ClientSettings, Credential, Descriptor, InMemorySessionLedger,
    LedgerFuture, Limits, Server, ServerSettings, SessionLedger, KEY_HEADER,
};
use bytes::{BufMut, Bytes, BytesMut};
use http::{Request, StatusCode};
use std::{
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, Notify},
    task::JoinHandle,
    time::{timeout, Instant},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

const DEADLINE: Duration = Duration::from_secs(10);
fn credential() -> Credential {
    Credential::from_private_bytes(Zeroizing::new(vec![b'a'; 64])).unwrap()
}
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
struct Running {
    server: Arc<Server>,
    settings: ClientSettings,
    key: Credential,
    descriptor: Descriptor,
    connector: TlsConnector,
    trusted_config: Arc<rustls::ClientConfig>,
    acceptor: TlsAcceptor,
    accepted: mpsc::Receiver<aegis_web_carrier::AcceptedSession>,
    sender: mpsc::Sender<aegis_web_carrier::AcceptedSession>,
    stop: Cancellation,
    task: JoinHandle<io::Result<()>>,
    limits: Limits,
}
impl Running {
    async fn new(limits: Limits, html: String) -> Self {
        Self::with_ledger(limits, html, Arc::new(InMemorySessionLedger::default())).await
    }
    async fn with_ledger(limits: Limits, html: String, ledger: Arc<dyn SessionLedger>) -> Self {
        let (acceptor, trusted_config) = configs();
        let connector = TlsConnector::from(trusted_config.clone());
        let settings = ClientSettings {
            authority: "site.test".into(),
            descriptor_path: "/private/descriptor".into(),
            credential_file: PathBuf::from(if cfg!(windows) {
                "C:/fixture/private/key"
            } else {
                "/fixture/private/key"
            }),
        };
        let key = credential();
        let server = Server::with_ledger(
            ServerSettings {
                client: settings.clone(),
                site_html: html,
            },
            key.clone(),
            limits.clone(),
            ledger,
        )
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, accepted) = mpsc::channel(limits.max_sessions);
        let stop = Cancellation::default();
        let task = tokio::spawn(server.clone().serve(
            listener,
            acceptor.clone(),
            sender.clone(),
            stop.clone(),
        ));
        let descriptor = Client::discover(connector.clone(), address, &settings, &key, &limits)
            .await
            .unwrap();
        Self {
            server,
            settings,
            key,
            descriptor,
            connector,
            trusted_config,
            acceptor,
            accepted,
            sender,
            stop,
            task,
            limits,
        }
    }
    async fn client(&self) -> aegis_web_carrier::WebStream {
        Client::connect(
            self.connector.clone(),
            &self.settings,
            self.descriptor.clone(),
            self.key.clone(),
            self.limits.clone(),
        )
        .await
        .unwrap()
    }
    async fn finish(self) {
        self.stop.cancel();
        timeout(DEADLINE, self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(self.server.stats().active_sessions, 0);
        assert_eq!(self.server.stats().active_connections, 0);
        assert_eq!(self.server.stats().active_requests, 0);
    }
}
struct Raw {
    send: h2::client::SendRequest<Bytes>,
    driver: JoinHandle<()>,
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl Raw {
    async fn new(connector: TlsConnector, address: SocketAddr, window: u32) -> Self {
        let tcp = TcpStream::connect(address).await.unwrap();
        let name = rustls::pki_types::ServerName::try_from("site.test").unwrap();
        let tls = connector.connect(name, tcp).await.unwrap();
        let mut builder = h2::client::Builder::new();
        builder.initial_window_size(window);
        let (send, connection) = builder.handshake::<_, Bytes>(tls).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        Self { send, driver }
    }
    async fn request(&mut self, request: Request<()>, body: Bytes) -> (StatusCode, Bytes) {
        self.send = self.send.clone().ready().await.unwrap();
        let (response, mut send) = self.send.send_request(request, body.is_empty()).unwrap();
        if !body.is_empty() {
            send.send_data(body, true).unwrap();
        }
        let response = response.await.unwrap();
        let status = response.status();
        let mut receive = response.into_body();
        let mut body = BytesMut::new();
        while let Some(chunk) = receive.data().await {
            let chunk = chunk.unwrap();
            receive
                .flow_control()
                .release_capacity(chunk.len())
                .unwrap();
            body.extend_from_slice(&chunk);
        }
        (status, body.freeze())
    }
    async fn frame(
        &mut self,
        r: &Running,
        id: [u8; 32],
        sequence: u64,
        ack: u64,
        flags: u8,
        data: &[u8],
    ) -> (StatusCode, Bytes) {
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://site.test{}", r.descriptor.path))
            .header("content-type", "application/octet-stream")
            .header(KEY_HEADER, r.key.header_value())
            .body(())
            .unwrap();
        self.request(request, frame(id, sequence, ack, flags, data))
            .await
    }
}
fn frame(id: [u8; 32], sequence: u64, ack: u64, flags: u8, data: &[u8]) -> Bytes {
    let mut body = BytesMut::new();
    body.extend_from_slice(b"AWR1");
    body.extend_from_slice(&id);
    body.put_u64(sequence);
    body.put_u64(ack);
    body.put_u8(flags);
    body.extend_from_slice(data);
    body.freeze()
}
async fn until_empty(server: &Server) {
    timeout(Duration::from_secs(3), async {
        while server.stats().active_sessions != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ledger_capacity_reclaimed_after_each_closed_session() {
    timeout(DEADLINE, async {
        let limits = Limits {
            max_sessions: 1,
            unauthenticated_timeout: Duration::from_millis(100),
            ..Limits::default()
        };
        let ledger = Arc::new(InMemorySessionLedger::with_capacity(1).unwrap());
        let mut running = Running::with_ledger(limits, "<title>Site</title>".into(), ledger).await;
        for number in 1..=3 {
            let id = [number; 32];
            let raw = timeout(Duration::from_secs(2), async {
                loop {
                    let mut raw =
                        Raw::new(running.connector.clone(), running.descriptor.ingress, 65535)
                            .await;
                    let status = raw.frame(&running, id, 0, 0, 1, b"").await.0;
                    if status == StatusCode::OK {
                        break raw;
                    }
                    drop(raw);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            drop(running.accepted.recv().await.unwrap());
            drop(raw);
            until_empty(&running.server).await;
        }
        running.finish().await;
    })
    .await
    .unwrap();
}

// OPEN and application-drop happen between the corresponding client timestamps.
// A network round trip may cross expiration, so classify by these absolute bounds,
// never by an assumed number of requests that fit into the lifetime.
async fn poll_until_expiration(
    raw: &mut Raw,
    r: &Running,
    id: [u8; 32],
    earliest: Instant,
    latest: Instant,
) {
    for sequence in 1.. {
        tokio::time::sleep(Duration::from_millis(25)).await;
        let sent_at = Instant::now();
        let status = raw.frame(r, id, sequence, sequence - 1, 0, b"").await.0;
        match status {
            StatusCode::OK => assert!(
                sent_at < latest,
                "poll admitted after the latest possible fixed expiration"
            ),
            StatusCode::NOT_FOUND => {
                assert!(
                    Instant::now() >= earliest,
                    "session rejected before the earliest possible fixed expiration"
                );
                return;
            }
            other => panic!("unexpected polling status: {other}"),
        }
    }
}

#[tokio::test]
async fn ordinary_h1_h2_site_and_exact_private_descriptor() {
    timeout(DEADLINE, async {
        let html = format!(
            "<!doctype html><title>Ordinary site</title>{}",
            "x".repeat(40_000)
        );
        let r = Running::new(Limits::default(), html.clone()).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 1024).await;
        let root = Request::builder()
            .uri("https://site.test/")
            .body(())
            .unwrap();
        let (status, body) = raw.request(root, Bytes::new()).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.as_ref() == html.as_bytes());
        let root = Request::builder()
            .method("HEAD")
            .uri("https://site.test/")
            .body(())
            .unwrap();
        assert!(raw.request(root, Bytes::new()).await.1.is_empty());
        for uri in [
            "https://site.test/private/descriptor",
            "https://site.test/anything",
            "https://other.test/",
        ] {
            let request = Request::builder().uri(uri).body(()).unwrap();
            let (status, body) = raw.request(request, Bytes::new()).await;
            assert_eq!(status, StatusCode::NOT_FOUND);
            assert!(body == Bytes::from_static(b"Not found\n"));
        }
        let request = Request::builder()
            .method("POST")
            .uri("https://site.test/private/descriptor")
            .header("content-type", "application/octet-stream")
            .header(KEY_HEADER, r.key.header_value())
            .header(KEY_HEADER, r.key.header_value())
            .body(())
            .unwrap();
        assert_eq!(
            raw.request(request, Bytes::new()).await.0,
            StatusCode::NOT_FOUND
        );
        let descriptor = Client::discover(
            r.connector.clone(),
            r.descriptor.ingress,
            &r.settings,
            &r.key,
            &r.limits,
        )
        .await
        .unwrap();
        assert_eq!(descriptor, r.descriptor);
        // Explicit H1 ALPN, verified certificate, actual public HTTP exchange.
        let mut h1_config = (*r.trusted_config).clone();
        h1_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let h1 = TlsConnector::from(Arc::new(h1_config));
        for (request, expected, head) in [
            ("GET / HTTP/1.1\r\nHost: site.test\r\n\r\n", 200, false),
            ("HEAD / HTTP/1.1\r\nHost: site.test\r\n\r\n", 200, true),
            (
                "GET /private/descriptor HTTP/1.1\r\nHost: site.test\r\n\r\n",
                404,
                false,
            ),
            (
                "GET / HTTP/1.1\r\nHost: site.test\r\nHost: site.test\r\n\r\n",
                404,
                false,
            ),
            (
                "GET / HTTP/1.1\r\nHost: site.test\r\nTransfer-Encoding: chunked\r\n\r\n",
                404,
                false,
            ),
        ] {
            let tcp = TcpStream::connect(r.descriptor.ingress).await.unwrap();
            let mut tls = h1
                .connect(
                    rustls::pki_types::ServerName::try_from("site.test").unwrap(),
                    tcp,
                )
                .await
                .unwrap();
            assert_eq!(
                tls.get_ref().1.alpn_protocol(),
                Some(b"http/1.1".as_slice())
            );
            tls.write_all(request.as_bytes()).await.unwrap();
            let mut response = Vec::new();
            tls.read_to_end(&mut response).await.unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {expected}")));
            let (_, body) = response.split_once("\r\n\r\n").unwrap();
            assert!(
                body == if head {
                    ""
                } else if expected == 200 {
                    &html
                } else {
                    "Not found\n"
                }
            );
        }
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordered_deferred_duplex_large_payload_and_half_close() {
    timeout(DEADLINE, async {
        let mut r = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let mut client = r.client().await;
        let accepted = r.accepted.recv().await.unwrap();
        assert!(accepted.peer_ip().is_loopback());
        let (mut server, authentication) = accepted.into_parts();
        authentication.mark_authenticated().unwrap();
        let payload: Vec<u8> = (0..100_123).map(|i| (i % 251) as u8).collect();
        let server_length = payload.len();
        let application = tokio::spawn(async move {
            let mut bytes = vec![0; server_length];
            server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(server.read(&mut [0; 1]).await.unwrap(), 0);
            server.write_all(&bytes).await.unwrap();
            server.shutdown().await.unwrap();
        });
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        assert!(reply == payload);
        application.await.unwrap();
        client.cancel().await;
        until_empty(&r.server).await;
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn ordered_download_fin_keeps_upload_half_open() {
    timeout(DEADLINE, async {
        let mut r = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let mut client = r.client().await;
        let (mut application, authentication) = r.accepted.recv().await.unwrap().into_parts();
        authentication.mark_authenticated().unwrap();
        assert_eq!(client.read(&mut []).await.unwrap(), 0);
        application.shutdown().await.unwrap();
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        client
            .write_all(b"upload after download FIN")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        let mut bytes = Vec::new();
        application.read_to_end(&mut bytes).await.unwrap();
        assert_eq!(bytes, b"upload after download FIN");
        drop(application);
        client.cancel().await;
        until_empty(&r.server).await;
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn abrupt_carrier_stop_is_an_error_not_clean_eof() {
    timeout(DEADLINE, async {
        let mut r = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let mut client = r.client().await;
        let (application, authentication) = r.accepted.recv().await.unwrap().into_parts();
        authentication.mark_authenticated().unwrap();
        // Keep the application alive without sending its ordered FIN. Stopping
        // the actual TLS/H2 listener must not masquerade as successful delivery.
        r.finish().await;
        let result = timeout(Duration::from_secs(2), client.read(&mut [0; 1]))
            .await
            .unwrap();
        assert!(
            result.is_err(),
            "abrupt carrier loss was exposed as {result:?}"
        );
        assert!(client.write_all(b"after carrier loss").await.is_err());
        drop(application);
        client.cancel().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn exact_request_retry_is_idempotent_and_conflicting_sequence_rejected() {
    timeout(DEADLINE, async {
        let mut r = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        let id = [7; 32];
        assert_eq!(raw.frame(&r, id, 0, 0, 1, b"").await.0, StatusCode::OK);
        let (mut application, auth) = r.accepted.recv().await.unwrap().into_parts();
        auth.mark_authenticated().unwrap();
        let (status, first) = raw.frame(&r, id, 1, 0, 0, b"once").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            first.len(),
            45,
            "current upload must not populate its own response"
        );
        let duplicate = raw.frame(&r, id, 1, 0, 0, b"once").await;
        assert_eq!(duplicate.0, StatusCode::OK);
        assert!(duplicate.1 == first);
        let mut input = [0; 4];
        application.read_exact(&mut input).await.unwrap();
        assert!(input == *b"once");
        assert!(
            timeout(Duration::from_millis(30), application.read(&mut [0; 1]))
                .await
                .is_err()
        );
        assert_eq!(
            raw.frame(&r, id, 1, 0, 0, b"conflict").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            raw.frame(&r, id, 3, 2, 0, b"").await.0,
            StatusCode::NOT_FOUND
        );
        application.write_all(b"prepared").await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let response = raw.frame(&r, id, 2, 1, 0, b"").await;
        assert_eq!(response.0, StatusCode::OK);
        assert!(&response.1[45..] == b"prepared");
        // The same nonce on a new outer connection cannot resume/replay this session.
        let mut other = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        assert_eq!(
            other.frame(&r, id, 2, 1, 0, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            raw.frame(&r, id, 3, 2, 4, b"").await.0,
            StatusCode::NOT_FOUND
        );
        until_empty(&r.server).await;
        drop(raw);
        drop(other);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn fixed_preauth_expiration_quota_and_drop_cancel() {
    timeout(DEADLINE, async {
        let limits = Limits {
            max_sessions: 1,
            unauthenticated_timeout: Duration::from_millis(300),
            ..Limits::default()
        };
        let mut r = Running::new(limits, "<title>Site</title>".into()).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        assert_eq!(raw.frame(&r, [8; 32], 0, 0, 1, b"").await.0, StatusCode::OK);
        let accepted = r.accepted.recv().await.unwrap();
        assert_eq!(
            raw.frame(&r, [9; 32], 0, 0, 1, b"").await.0,
            StatusCode::NOT_FOUND
        );
        // Successful empty polls cannot extend the unauthenticated deadline.
        for sequence in 1..5 {
            assert_eq!(
                raw.frame(&r, [8; 32], sequence, sequence - 1, 0, b"")
                    .await
                    .0,
                StatusCode::OK
            );
            tokio::time::sleep(Duration::from_millis(40)).await;
        }
        until_empty(&r.server).await;
        let (stream, auth) = accepted.into_parts();
        assert!(auth.mark_authenticated().is_err());
        drop(stream);
        drop(raw);
        // A fresh descriptor/session is allowed after old quota is returned.
        r.descriptor = r.server.rotate_ingress(r.descriptor.ingress).unwrap();
        let client = r.client().await;
        let accepted = r.accepted.recv().await.unwrap();
        let (_stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        client.cancel().await;
        until_empty(&r.server).await;
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn actual_ingress_rotation_preserves_old_stream_and_denies_old_new_open() {
    timeout(DEADLINE, async {
        let mut r = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let old_descriptor = r.descriptor.clone();
        let mut old = r.client().await;
        let (old_server, auth) = r.accepted.recv().await.unwrap().into_parts();
        auth.mark_authenticated().unwrap();
        let echo = tokio::spawn(async move {
            let (mut read, mut write) = tokio::io::split(old_server);
            tokio::io::copy(&mut read, &mut write).await.unwrap();
            write.shutdown().await.unwrap();
        });
        let next = TcpListener::bind("127.0.0.1:0").await.unwrap();
        r.descriptor = r.server.rotate_ingress(next.local_addr().unwrap()).unwrap();
        let next_stop = Cancellation::default();
        let next_task = tokio::spawn(r.server.clone().serve(
            next,
            r.acceptor.clone(),
            r.sender.clone(),
            next_stop.clone(),
        ));
        old.write_all(b"survives rotation").await.unwrap();
        let mut reply = [0; 17];
        old.read_exact(&mut reply).await.unwrap();
        assert!(&reply == b"survives rotation");
        assert!(Client::connect(
            r.connector.clone(),
            &r.settings,
            old_descriptor,
            r.key.clone(),
            r.limits.clone()
        )
        .await
        .is_err());
        let published = Client::discover(
            r.connector.clone(),
            r.server.descriptor().unwrap().ingress,
            &r.settings,
            &r.key,
            &r.limits,
        )
        .await
        .unwrap();
        assert_eq!(published, r.descriptor);
        let mut new = r.client().await;
        let (mut server, auth) = r.accepted.recv().await.unwrap().into_parts();
        auth.mark_authenticated().unwrap();
        let new_application = tokio::spawn(async move {
            let mut input = [0; 3];
            server.read_exact(&mut input).await.unwrap();
            server.write_all(&input).await.unwrap();
            server.shutdown().await.unwrap();
        });
        new.write_all(b"new").await.unwrap();
        let mut result = [0; 3];
        new.read_exact(&mut result).await.unwrap();
        assert!(&result == b"new");
        new_application.await.unwrap();
        new.cancel().await;
        old.shutdown().await.unwrap();
        let mut end = Vec::new();
        old.read_to_end(&mut end).await.unwrap();
        echo.await.unwrap();
        old.cancel().await;
        next_stop.cancel();
        next_task.await.unwrap().unwrap();
        until_empty(&r.server).await;
        r.finish().await;
    })
    .await
    .unwrap();
}

// A new function instance with the same admission key has no prior session
// state. This is the actual HTTPS/H2 path through two separately owned server
// instances; it intentionally documents the migration boundary before any
// serverless deployment is proposed.
#[tokio::test]
async fn independent_instance_restart_rejects_old_session_and_admits_fresh_open() {
    timeout(DEADLINE, async {
        let mut first = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let old_id = [91; 32];
        let mut original = Raw::new(first.connector.clone(), first.descriptor.ingress, 65535).await;
        assert_eq!(
            original.frame(&first, old_id, 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let accepted = first.accepted.recv().await.unwrap();
        let (stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        let first_key = first.key.header_value();
        drop(stream);
        drop(original);
        first.finish().await;

        // The same synthetic admission secret is used after the restart; the
        // instance's session table and response path are new. A stale sequence
        // must never become a new application session.
        let mut restarted = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        assert!(first_key.as_bytes() == restarted.key.header_value().as_bytes());
        let mut next = Raw::new(
            restarted.connector.clone(),
            restarted.descriptor.ingress,
            65535,
        )
        .await;
        assert_eq!(
            next.frame(&restarted, old_id, 1, 0, 0, b"after restart")
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(restarted.server.stats().active_sessions, 0);
        assert_eq!(
            next.frame(&restarted, [92; 32], 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let accepted = restarted.accepted.recv().await.unwrap();
        let (stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        drop(stream);
        drop(next);
        restarted.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn independent_instance_replica_rejects_foreign_session_and_admits_fresh_open() {
    timeout(DEADLINE, async {
        let mut first = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let mut second = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        assert!(first.key.header_value().as_bytes() == second.key.header_value().as_bytes());
        let old_id = [93; 32];
        let mut original = Raw::new(first.connector.clone(), first.descriptor.ingress, 65535).await;
        assert_eq!(
            original.frame(&first, old_id, 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let first_session = first.accepted.recv().await.unwrap();
        let (first_stream, first_auth) = first_session.into_parts();
        first_auth.mark_authenticated().unwrap();

        // Both instances use the same synthetic admission key. The second
        // listener must still refuse an in-flight session owned by the first.
        let mut routed = Raw::new(second.connector.clone(), second.descriptor.ingress, 65535).await;
        assert_eq!(
            routed.frame(&second, old_id, 1, 0, 0, b"misrouted").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(second.server.stats().active_sessions, 0);
        assert_eq!(
            routed.frame(&second, [94; 32], 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let second_session = second.accepted.recv().await.unwrap();
        let (second_stream, second_auth) = second_session.into_parts();
        second_auth.mark_authenticated().unwrap();
        drop(first_stream);
        drop(second_stream);
        drop(original);
        drop(routed);
        first.finish().await;
        second.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shared_ledger_fences_replayed_open_across_replica_and_restart() {
    timeout(DEADLINE, async {
        let ledger: Arc<dyn SessionLedger> = Arc::new(InMemorySessionLedger::default());
        let mut first = Running::with_ledger(
            Limits::default(),
            "<title>Site</title>".into(),
            ledger.clone(),
        )
        .await;
        let second = Running::with_ledger(
            Limits::default(),
            "<title>Site</title>".into(),
            ledger.clone(),
        )
        .await;
        let id = [161; 32];
        let mut original = Raw::new(first.connector.clone(), first.descriptor.ingress, 65535).await;
        assert_eq!(
            original.frame(&first, id, 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        assert_eq!(
            original.frame(&first, id, 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let accepted = first.accepted.recv().await.unwrap();
        let (stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        let (status, first_reply) = original.frame(&first, id, 1, 0, 0, b"one").await;
        assert_eq!(status, StatusCode::OK);
        let (status, replay_reply) = original.frame(&first, id, 1, 0, 0, b"one").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(first_reply, replay_reply);
        let mut replica =
            Raw::new(second.connector.clone(), second.descriptor.ingress, 65535).await;
        assert_eq!(
            replica.frame(&second, id, 0, 0, 1, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            replica.frame(&second, id, 2, 1, 0, b"stale").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(second.server.stats().active_sessions, 0);
        drop(stream);
        drop(original);
        first.finish().await;

        let mut restarted =
            Running::with_ledger(Limits::default(), "<title>Site</title>".into(), ledger).await;
        let mut after = Raw::new(
            restarted.connector.clone(),
            restarted.descriptor.ingress,
            65535,
        )
        .await;
        assert_eq!(
            after.frame(&restarted, id, 0, 0, 1, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            after.frame(&restarted, id, 2, 1, 0, b"stale").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(restarted.server.stats().active_sessions, 0);
        assert_eq!(
            after.frame(&restarted, [162; 32], 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let accepted = restarted.accepted.recv().await.unwrap();
        let (stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        drop(stream);
        drop(after);
        drop(replica);
        second.finish().await;
        restarted.finish().await;
    })
    .await
    .unwrap();
}

struct GatedLedger {
    available: AtomicBool,
    inner: InMemorySessionLedger,
}
impl SessionLedger for GatedLedger {
    fn claim<'a>(&'a self, id: [u8; 32], owner: u64, expires_ms: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            if !self.available.load(Ordering::Acquire) {
                return Err(io::Error::other("store unavailable"));
            }
            self.inner.claim(id, owner, expires_ms).await
        })
    }
    fn verify<'a>(&'a self, id: [u8; 32], owner: u64, next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            if !self.available.load(Ordering::Acquire) {
                return Err(io::Error::other("store unavailable"));
            }
            self.inner.verify(id, owner, next).await
        })
    }
    fn advance<'a>(&'a self, id: [u8; 32], owner: u64, next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            if !self.available.load(Ordering::Acquire) {
                return Err(io::Error::other("store unavailable"));
            }
            self.inner.advance(id, owner, next).await
        })
    }
    fn release<'a>(&'a self, id: [u8; 32], owner: u64) -> LedgerFuture<'a> {
        self.inner.release(id, owner)
    }
}

#[tokio::test]
async fn unavailable_ledger_rejects_open_replay_and_advance() {
    timeout(DEADLINE, async {
        let ledger = Arc::new(GatedLedger {
            available: AtomicBool::new(false),
            inner: InMemorySessionLedger::default(),
        });
        let mut r = Running::with_ledger(
            Limits::default(),
            "<title>Site</title>".into(),
            ledger.clone(),
        )
        .await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        let id = [163; 32];
        assert_eq!(
            raw.frame(&r, id, 0, 0, 1, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(r.server.stats().active_sessions, 0);
        ledger.available.store(true, Ordering::Release);
        assert_eq!(raw.frame(&r, id, 0, 0, 1, b"").await.0, StatusCode::OK);
        let accepted = r.accepted.recv().await.unwrap();
        let (stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        ledger.available.store(false, Ordering::Release);
        assert_eq!(
            raw.frame(&r, id, 0, 0, 1, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            raw.frame(&r, id, 1, 0, 0, b"blocked").await.0,
            StatusCode::NOT_FOUND
        );
        drop(stream);
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DelayPoint {
    Claim,
    Verify,
    Advance,
}
struct DelayedLedgerAck {
    inner: InMemorySessionLedger,
    point: DelayPoint,
    committed: Notify,
    release: Notify,
}
impl DelayedLedgerAck {
    async fn hold(&self, point: DelayPoint) {
        if self.point == point {
            self.committed.notify_one();
            self.release.notified().await;
        }
    }
}
impl SessionLedger for DelayedLedgerAck {
    fn claim<'a>(&'a self, id: [u8; 32], owner: u64, expires_ms: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            self.inner.claim(id, owner, expires_ms).await?;
            self.hold(DelayPoint::Claim).await;
            Ok(())
        })
    }
    fn verify<'a>(&'a self, id: [u8; 32], owner: u64, next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            self.inner.verify(id, owner, next).await?;
            self.hold(DelayPoint::Verify).await;
            Ok(())
        })
    }
    fn advance<'a>(&'a self, id: [u8; 32], owner: u64, next: u64) -> LedgerFuture<'a> {
        Box::pin(async move {
            // Model a remote transaction that commits in time but whose success
            // response reaches the process only after its local lease expires.
            self.inner.advance(id, owner, next).await?;
            self.hold(DelayPoint::Advance).await;
            Ok(())
        })
    }
    fn release<'a>(&'a self, id: [u8; 32], owner: u64) -> LedgerFuture<'a> {
        self.inner.release(id, owner)
    }
}

#[tokio::test]
async fn delayed_ledger_ack_cannot_revive_expired_application_upload() {
    timeout(DEADLINE, async {
        let ledger = Arc::new(DelayedLedgerAck {
            inner: InMemorySessionLedger::default(),
            point: DelayPoint::Advance,
            committed: Notify::new(),
            release: Notify::new(),
        });
        let limits = Limits {
            max_lifetime: Duration::from_millis(400),
            ..Limits::default()
        };
        let mut r =
            Running::with_ledger(limits, "<title>Site</title>".into(), ledger.clone()).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        let id = [164; 32];
        assert_eq!(raw.frame(&r, id, 0, 0, 1, b"").await.0, StatusCode::OK);
        let accepted = r.accepted.recv().await.unwrap();
        let (mut stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        let (reply, ()) = tokio::join!(
            async { raw.frame(&r, id, 1, 0, 0, b"must not upload").await },
            async {
                ledger.committed.notified().await;
                tokio::time::sleep(Duration::from_millis(450)).await;
                ledger.release.notify_one();
            }
        );
        assert_eq!(reply.0, StatusCode::NOT_FOUND);
        let mut bytes = [0; 32];
        match timeout(Duration::from_millis(100), stream.read(&mut bytes)).await {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("expired request uploaded {n} application bytes"),
            Err(_) => {}
        }
        drop(stream);
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn delayed_claim_ack_cannot_admit_expired_descriptor() {
    timeout(DEADLINE, async {
        let ledger = Arc::new(DelayedLedgerAck {
            inner: InMemorySessionLedger::default(),
            point: DelayPoint::Claim,
            committed: Notify::new(),
            release: Notify::new(),
        });
        let limits = Limits {
            descriptor_lifetime: Duration::from_millis(400),
            ..Limits::default()
        };
        let mut r =
            Running::with_ledger(limits, "<title>Site</title>".into(), ledger.clone()).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        let (reply, ()) = tokio::join!(
            async { raw.frame(&r, [165; 32], 0, 0, 1, b"").await },
            async {
                ledger.committed.notified().await;
                tokio::time::sleep(Duration::from_millis(450)).await;
                ledger.release.notify_one();
            }
        );
        assert_eq!(reply.0, StatusCode::NOT_FOUND);
        assert_eq!(r.server.stats().active_sessions, 0);
        assert!(
            r.accepted.try_recv().is_err(),
            "expired OPEN reached application"
        );
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn delayed_verify_ack_cannot_return_cached_reply_after_expiry() {
    timeout(DEADLINE, async {
        let ledger = Arc::new(DelayedLedgerAck {
            inner: InMemorySessionLedger::default(),
            point: DelayPoint::Verify,
            committed: Notify::new(),
            release: Notify::new(),
        });
        let limits = Limits {
            max_lifetime: Duration::from_millis(400),
            ..Limits::default()
        };
        let mut r =
            Running::with_ledger(limits, "<title>Site</title>".into(), ledger.clone()).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        let id = [166; 32];
        assert_eq!(raw.frame(&r, id, 0, 0, 1, b"").await.0, StatusCode::OK);
        let accepted = r.accepted.recv().await.unwrap();
        let (stream, auth) = accepted.into_parts();
        auth.mark_authenticated().unwrap();
        let (reply, ()) = tokio::join!(async { raw.frame(&r, id, 0, 0, 1, b"").await }, async {
            ledger.committed.notified().await;
            tokio::time::sleep(Duration::from_millis(450)).await;
            ledger.release.notify_one();
        });
        assert_eq!(reply.0, StatusCode::NOT_FOUND);
        assert!(
            r.accepted.try_recv().is_err(),
            "replay admitted a second application"
        );
        drop(stream);
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[cfg(unix)]
#[path = "support/inner_mtls.rs"]
mod inner_mtls;

#[tokio::test]
async fn initial_descriptor_is_published_and_expired_descriptor_cannot_admit_new_open() {
    timeout(DEADLINE, async {
        let limits = Limits {
            descriptor_lifetime: Duration::from_millis(100),
            ..Limits::default()
        };
        let r = Running::new(limits, "<title>Site</title>".into()).await;
        assert_eq!(r.descriptor.generation, 1);
        assert!(r.server.descriptor().is_ok());
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(r.server.descriptor().is_err());
        assert!(Client::discover(
            r.connector.clone(),
            r.descriptor.ingress,
            &r.settings,
            &r.key,
            &r.limits
        )
        .await
        .is_err());
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        assert_eq!(
            raw.frame(&r, [29; 32], 0, 0, 1, b"").await.0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(r.server.stats().active_sessions, 0);
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn zero_receive_window_and_oversized_body_release_request_quota() {
    timeout(DEADLINE, async {
        let limits = Limits {
            request_timeout: Duration::from_millis(120),
            unauthenticated_timeout: Duration::from_millis(300),
            ..Limits::default()
        };
        let r = Running::new(limits, "x".repeat(32_000)).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 0).await;
        raw.send = raw.send.clone().ready().await.unwrap();
        let (response, _) = raw
            .send
            .send_request(
                Request::builder()
                    .uri("https://site.test/")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let result = timeout(Duration::from_secs(2), response.into_body().data()).await;
        assert!(
            matches!(result, Ok(Some(Err(_))) | Ok(None)),
            "zero-window reply falsely completed with body bytes"
        );
        timeout(Duration::from_secs(2), async {
            while r.server.stats().active_requests != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        drop(raw);
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        assert_eq!(
            raw.frame(&r, [33; 32], 0, 0, 1, &vec![0; r.limits.frame_bytes + 1])
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(r.server.stats().active_sessions, 0);
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn authenticated_application_end_and_max_age_are_fixed_not_poll_renewable() {
    timeout(DEADLINE, async {
        let limits = Limits {
            request_timeout: Duration::from_millis(200),
            max_lifetime: Duration::from_millis(300),
            ..Limits::default()
        };
        let mut r = Running::new(limits, "<title>Site</title>".into()).await;
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        let open_started = Instant::now();
        assert_eq!(
            raw.frame(&r, [17; 32], 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let open_completed = Instant::now();
        let (application, auth) = r.accepted.recv().await.unwrap().into_parts();
        auth.mark_authenticated().unwrap();
        let drop_started = Instant::now();
        drop(application);
        let drop_completed = Instant::now();
        poll_until_expiration(
            &mut raw,
            &r,
            [17; 32],
            (open_started + r.limits.max_lifetime).min(drop_started + r.limits.request_timeout),
            (open_completed + r.limits.max_lifetime).min(drop_completed + r.limits.request_timeout),
        )
        .await;
        until_empty(&r.server).await;
        assert!(auth.mark_authenticated().is_err());
        drop(raw);
        let mut raw = Raw::new(r.connector.clone(), r.descriptor.ingress, 65535).await;
        let open_started = Instant::now();
        assert_eq!(
            raw.frame(&r, [18; 32], 0, 0, 1, b"").await.0,
            StatusCode::OK
        );
        let open_completed = Instant::now();
        let (application, auth) = r.accepted.recv().await.unwrap().into_parts();
        auth.mark_authenticated().unwrap();
        poll_until_expiration(
            &mut raw,
            &r,
            [18; 32],
            open_started + r.limits.max_lifetime,
            open_completed + r.limits.max_lifetime,
        )
        .await;
        until_empty(&r.server).await;
        assert!(auth.mark_authenticated().is_err());
        drop(application);
        drop(raw);
        r.finish().await;
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn descriptor_authority_and_outer_certificate_are_verified_before_open() {
    timeout(DEADLINE, async {
        let r = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let (_, wrong_roots) = configs();
        let wrong = TlsConnector::from(wrong_roots);
        assert!(
            Client::discover(wrong, r.descriptor.ingress, &r.settings, &r.key, &r.limits)
                .await
                .is_err()
        );
        let mut foreign = r.descriptor.clone();
        foreign.authority = "other.test".into();
        assert!(Client::connect(
            r.connector.clone(),
            &r.settings,
            foreign,
            r.key.clone(),
            r.limits.clone()
        )
        .await
        .is_err());
        let mut expired = r.descriptor.clone();
        expired.expires_unix_ms = 1;
        assert!(Client::connect(
            r.connector.clone(),
            &r.settings,
            expired,
            r.key.clone(),
            r.limits.clone()
        )
        .await
        .is_err());
        assert_eq!(r.server.stats().active_sessions, 0);
        assert!(r.key.header_value().is_sensitive());
        assert_eq!(format!("{:?}", r.key), "Credential([redacted])");
        r.finish().await;
    })
    .await
    .unwrap();
}
