use super::*;
use aegis_core::relay_geneva::RelaySocketGuard;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Wake, Waker};
use tokio::io::AsyncWrite;
use tokio::net::{TcpListener, TcpStream};

enum ReadOutcome {
    Bytes(Vec<u8>),
    WouldBlock,
    Error(i32),
}

struct ControlSource {
    worker_error: Option<i32>,
    checks: Arc<AtomicUsize>,
    readiness_polls: Arc<AtomicUsize>,
    read_attempts: Arc<AtomicUsize>,
    drops: Arc<AtomicUsize>,
    outcome: Mutex<ReadOutcome>,
}

impl Drop for ControlSource {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::AcqRel);
    }
}

impl ReadinessSource for ControlSource {
    fn check_worker(&self) -> io::Result<()> {
        self.checks.fetch_add(1, Ordering::AcqRel);
        match self.worker_error {
            Some(raw) => Err(io::Error::from_raw_os_error(raw)),
            None => Ok(()),
        }
    }

    fn poll_read_ready(&self, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.readiness_polls.fetch_add(1, Ordering::AcqRel);
        Poll::Ready(Ok(()))
    }

    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_attempts.fetch_add(1, Ordering::AcqRel);
        match &*self.outcome.lock().unwrap() {
            ReadOutcome::Bytes(bytes) => {
                let len = bytes.len().min(buf.len());
                buf[..len].copy_from_slice(&bytes[..len]);
                Ok(len)
            }
            ReadOutcome::WouldBlock => Err(io::ErrorKind::WouldBlock.into()),
            ReadOutcome::Error(raw) => Err(io::Error::from_raw_os_error(*raw)),
        }
    }
}

impl AsyncWrite for ControlSource {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct WakeCounter(Arc<AtomicUsize>);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

fn control_source(
    outcome: ReadOutcome,
) -> (
    ControlSource,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
    Arc<AtomicUsize>,
) {
    let checks = Arc::new(AtomicUsize::new(0));
    let readiness = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new(AtomicUsize::new(0));
    let drops = Arc::new(AtomicUsize::new(0));
    (
        ControlSource {
            worker_error: None,
            checks: checks.clone(),
            readiness_polls: readiness.clone(),
            read_attempts: reads.clone(),
            drops: drops.clone(),
            outcome: Mutex::new(outcome),
        },
        checks,
        readiness,
        reads,
        drops,
    )
}

#[test]
fn worker_guard_precedes_even_an_empty_read() {
    let (mut source, checks, readiness, reads, _) = control_source(ReadOutcome::Bytes(vec![]));
    source.worker_error = Some(12_345);
    let mut stream = WindowsRustlsTcp::new(source);
    let waker = Waker::from(Arc::new(WakeCounter(Arc::new(AtomicUsize::new(0)))));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [];
    let mut read_buf = ReadBuf::new(&mut storage);
    let error = match Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf) {
        Poll::Ready(Err(error)) => error,
        other => panic!("worker failure must be ready, got {other:?}"),
    };
    assert_eq!(error.raw_os_error(), Some(12_345));
    assert_eq!(checks.load(Ordering::Acquire), 1);
    assert_eq!(readiness.load(Ordering::Acquire), 0);
    assert_eq!(reads.load(Ordering::Acquire), 0);
}

#[test]
fn one_ready_would_block_attempt_yields_and_wakes_once() {
    let (source, _, readiness, reads, _) = control_source(ReadOutcome::WouldBlock);
    let mut stream = WindowsRustlsTcp::new(source);
    let wakes = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(WakeCounter(wakes.clone())));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0; 8];
    let mut read_buf = ReadBuf::new(&mut storage);
    assert!(Pin::new(&mut stream)
        .poll_read(&mut cx, &mut read_buf)
        .is_pending());
    assert_eq!(readiness.load(Ordering::Acquire), 1);
    assert_eq!(reads.load(Ordering::Acquire), 1);
    assert_eq!(wakes.load(Ordering::Acquire), 1);
}

#[test]
fn eof_and_raw_read_errors_are_preserved() {
    let (source, _, _, reads, _) = control_source(ReadOutcome::Bytes(vec![]));
    let mut stream = WindowsRustlsTcp::new(source);
    let waker = Waker::from(Arc::new(WakeCounter(Arc::new(AtomicUsize::new(0)))));
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0; 8];
    let mut read_buf = ReadBuf::new(&mut storage);
    assert!(matches!(
        Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(read_buf.filled().len(), 0);
    assert_eq!(reads.load(Ordering::Acquire), 1);

    let (source, _, _, _, _) = control_source(ReadOutcome::Error(12_346));
    let mut stream = WindowsRustlsTcp::new(source);
    let mut storage = [0; 8];
    let mut read_buf = ReadBuf::new(&mut storage);
    let error = match Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf) {
        Poll::Ready(Err(error)) => error,
        other => panic!("read error must be ready, got {other:?}"),
    };
    assert_eq!(error.raw_os_error(), Some(12_346));
    assert_eq!(error.kind(), io::Error::from_raw_os_error(12_346).kind());
}

#[test]
fn dropping_adapter_drops_its_owned_worker_guard_source() {
    let (source, _, _, _, drops) = control_source(ReadOutcome::Bytes(vec![]));
    let stream = WindowsRustlsTcp::new(source);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    drop(stream);
    assert_eq!(drops.load(Ordering::Acquire), 1);
}

struct FaultSource {
    inner: RelayProtectedTcp,
    armed: Arc<AtomicBool>,
    injected: Arc<AtomicUsize>,
    stash: Mutex<Vec<u8>>,
}

struct SyntheticGuard {
    failed: Arc<AtomicBool>,
    closes: Arc<AtomicUsize>,
}

impl RelaySocketGuard for SyntheticGuard {
    fn failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }

    fn close(&mut self) {
        self.closes.fetch_add(1, Ordering::AcqRel);
    }
}

#[tokio::test]
async fn real_protected_socket_preserves_failure_and_guard_drop_ownership() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tcp, accepted) = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        tokio::join!(TcpStream::connect(address), listener.accept())
    })
    .await
    .expect("real protected-socket fixture exceeded original establishment bound");
    let tcp = tcp.unwrap();
    let peer = accepted.unwrap().0;
    let failed = Arc::new(AtomicBool::new(false));
    let closes = Arc::new(AtomicUsize::new(0));
    let protected = RelayProtectedTcp::protected(
        tcp,
        Box::new(SyntheticGuard {
            failed: failed.clone(),
            closes: closes.clone(),
        }),
    )
    .unwrap();
    let mut stream = WindowsRustlsTcp::new(protected);
    failed.store(true, Ordering::Release);
    let waker = Waker::from(Arc::new(WakeCounter(Arc::new(AtomicUsize::new(0)))));
    let mut cx = Context::from_waker(&waker);
    let mut empty = [];
    let mut read_buf = ReadBuf::new(&mut empty);
    let error = match Pin::new(&mut stream).poll_read(&mut cx, &mut read_buf) {
        Poll::Ready(Err(error)) => error,
        other => panic!("failed real guard must fail before empty read, got {other:?}"),
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
    assert_eq!(closes.load(Ordering::Acquire), 0);
    drop(stream);
    assert_eq!(closes.load(Ordering::Acquire), 1);
    drop(peer);
}

impl ReadinessSource for FaultSource {
    fn check_worker(&self) -> io::Result<()> {
        self.inner.check_worker()
    }

    fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.stash.lock().unwrap().is_empty() {
            return Poll::Ready(Ok(()));
        }
        (*self.inner).poll_read_ready(cx)
    }

    fn try_read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut stash = self.stash.lock().unwrap();
        if !stash.is_empty() {
            let len = stash.len().min(buf.len());
            buf[..len].copy_from_slice(&stash[..len]);
            stash.drain(..len);
            return Ok(len);
        }
        if self.armed.load(Ordering::Acquire)
            && self
                .injected
                .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
        {
            let mut captured = vec![0; buf.len().max(1)];
            let len = (*self.inner).try_read(&mut captured)?;
            captured.truncate(len);
            *stash = captured;
            return Err(io::ErrorKind::WouldBlock.into());
        }
        (*self.inner).try_read(buf)
    }
}

impl AsyncWrite for FaultSource {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn actual_tcp_rustls_h2_progresses_after_one_ready_would_block() {
    use super::super::grpc::{grpc_frame, read_grpc_message};
    use aegis_core::tunnel::{
        open_tunnel_request, open_tunnel_response, seal_tunnel_request, seal_tunnel_response,
        TunnelRequest, TunnelResponse, TunnelStatus,
    };
    use anyhow::Context as _;

    const AUTH: &[u8] = b"fairness-owned-fixture-only";
    const UP: &[u8] = b"fairness-client-marker-a7";
    const DOWN: &[u8] = b"fairness-server-marker-b9";
    const PATH: &str = "/aegis.tunnel.v1.TunnelService/Open";

    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(identity.cert.der().clone()).unwrap();
    let mut client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    client_config.key_log = Arc::new(rustls::NoKeyLog);
    let mut server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![identity.cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(identity.key_pair.serialize_der())),
    )
    .unwrap();
    server_config.alpn_protocols = vec![b"h2".to_vec()];
    server_config.key_log = Arc::new(rustls::NoKeyLog);

    // JoinSet is the RAII abort owner if the test unwinds. On every normal
    // error/timeout/success path below, abort then explicitly join both tasks.
    let mut owners: tokio::task::JoinSet<anyhow::Result<()>> = tokio::task::JoinSet::new();
    let open_count = Arc::new(AtomicUsize::new(0));
    let opens = open_count.clone();
    let phase = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        owners.spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(tcp)
                .await?;
            anyhow::ensure!(
                tls.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
                    && tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()),
                "server TLS negotiation differs from fixture contract"
            );
            let mut connection = h2::server::handshake(tls).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .context("server closed before request")??;
            anyhow::ensure!(
                request.method() == http::Method::POST && request.uri().path() == PATH,
                "production-shaped request missing"
            );
            let exchange = async move {
                let mut receive = request.into_body();
                let mut pending = Vec::new();
                let sealed_open = read_grpc_message(&mut receive, &mut pending)
                    .await?
                    .context("server did not receive framed OPEN")?;
                let open = open_tunnel_request(&sealed_open, AUTH)?;
                anyhow::ensure!(
                    open.host == "owned-fixture.example" && open.port == 8443,
                    "validated OPEN target differs from synthetic fixture"
                );
                anyhow::ensure!(
                    opens.fetch_add(1, Ordering::AcqRel) == 0,
                    "more than one validated OPEN"
                );
                let response = http::Response::builder()
                    .status(200)
                    .header("content-type", "application/grpc")
                    .body(())?;
                let mut send = respond.send_response(response, false)?;
                let sealed_ack = seal_tunnel_response(
                    &TunnelResponse {
                        status: TunnelStatus::Ok,
                        message: String::new(),
                    },
                    AUTH,
                )?;
                send.send_data(grpc_frame(&sealed_ack), false)?;
                let up = read_grpc_message(&mut receive, &mut pending)
                    .await?
                    .context("server did not receive upload marker")?;
                anyhow::ensure!(up == UP, "upload marker changed");
                anyhow::ensure!(
                    read_grpc_message(&mut receive, &mut pending)
                        .await?
                        .is_none(),
                    "unexpected extra OPEN/upload frame"
                );
                send.send_data(grpc_frame(DOWN), true)?;
                anyhow::Ok(())
            };
            tokio::pin!(exchange);
            // Read/body and queued-write progress require this same connection
            // owner to be polled concurrently. No secondary unowned driver.
            tokio::select! {
                result = &mut exchange => result?,
                result = std::future::poll_fn(|cx| connection.poll_closed(cx)) => {
                    result?;
                    anyhow::bail!("server H2 closed before protocol exchange");
                },
            }
            // Continue driving queued ACK/download through TLS until the
            // explicitly owned final cancellation; no queue==delivery claim.
            std::future::poll_fn(|cx| connection.poll_closed(cx)).await?;
            anyhow::Ok(())
        });

        let tcp = TcpStream::connect(address).await?;
        let armed = Arc::new(AtomicBool::new(false));
        let injected = Arc::new(AtomicUsize::new(0));
        let source = FaultSource {
            inner: tcp.into(),
            armed: armed.clone(),
            injected: injected.clone(),
            stash: Mutex::new(Vec::new()),
        };
        let tls = tokio_rustls::TlsConnector::from(Arc::new(client_config))
            .connect(
                ServerName::try_from("localhost")?,
                WindowsRustlsTcp::new(source),
            )
            .await?;
        anyhow::ensure!(
            tls.get_ref().1.protocol_version() == Some(rustls::ProtocolVersion::TLSv1_3)
                && tls.get_ref().1.alpn_protocol() == Some(b"h2".as_slice()),
            "verified client TLS negotiation differs from fixture contract"
        );
        let (mut client, mut connection) = super::super::surface::chrome_like_h2_builder()
            .handshake(tls)
            .await?;
        let mut ping = connection
            .ping_pong()
            .context("client ping owner missing")?;
        owners.spawn(async move {
            connection.await?;
            anyhow::Ok(())
        });
        // A real PING acknowledgement proves peer H2 progress/SETTINGS before
        // the one controlled post-handshake read fault is armed.
        ping.ping(h2::Ping::opaque()).await?;
        drop(ping);
        armed.store(true, Ordering::Release);

        let request = http::Request::builder()
            .method("POST")
            .uri(format!("https://localhost{PATH}"))
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())?;
        let (response, mut send) = client.send_request(request, false)?;
        let sealed_open = seal_tunnel_request(
            &TunnelRequest {
                host: "owned-fixture.example".into(),
                port: 8443,
            },
            AUTH,
        )?;
        send.send_data(grpc_frame(&sealed_open), false)?;
        let response = response.await?;
        anyhow::ensure!(response.status().is_success(), "response headers missing");
        let mut receive = response.into_body();
        let mut pending = Vec::new();
        let sealed_ack = read_grpc_message(&mut receive, &mut pending)
            .await?
            .context("client did not receive framed ACK")?;
        let ack = open_tunnel_response(&sealed_ack, AUTH)?;
        anyhow::ensure!(
            ack.status == TunnelStatus::Ok && ack.message.is_empty(),
            "validated ACK refused"
        );
        send.send_data(grpc_frame(UP), true)?;
        let down = read_grpc_message(&mut receive, &mut pending)
            .await?
            .context("client did not receive download marker")?;
        anyhow::ensure!(down == DOWN, "download marker changed");
        anyhow::ensure!(
            read_grpc_message(&mut receive, &mut pending)
                .await?
                .is_none(),
            "unexpected extra download frame"
        );
        anyhow::ensure!(
            open_count.load(Ordering::Acquire) == 1,
            "OPEN count differs from one"
        );
        anyhow::ensure!(
            injected.load(Ordering::Acquire) == 1,
            "controlled read fault was not reached"
        );
        drop(send);
        drop(receive);
        drop(client);
        anyhow::Ok(())
    })
    .await;

    owners.abort_all();
    let cleanup = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        let mut failed = None;
        while let Some(joined) = owners.join_next().await {
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) if failed.is_none() => failed = Some(error),
                Err(error) if !error.is_cancelled() && failed.is_none() => {
                    failed = Some(anyhow::anyhow!("owned fixture task panicked"));
                }
                _ => {}
            }
        }
        match failed {
            Some(error) => Err(error),
            None => anyhow::Ok(()),
        }
    })
    .await;
    cleanup
        .expect("owned fixture cleanup deadline")
        .expect("owned fixture task failure");
    assert!(owners.is_empty(), "all owned fixture tasks must be joined");
    phase
        .expect("original ten-second protocol bound")
        .expect("actual production-protocol fixture");
}
