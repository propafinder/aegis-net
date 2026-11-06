//! Authored boundary regressions only; no execution is claimed by this proposal.
use super::*;
use aegis_server::phase_witness::IoWitness;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicU8, Ordering},
    Mutex,
};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[derive(Default)]
struct Gate {
    mode: AtomicU8,
    wake: Mutex<Option<Waker>>,
}
impl Gate {
    fn set(&self, mode: u8) {
        self.mode.store(mode, Ordering::Release);
        if let Some(wake) = self.wake.lock().unwrap().take() {
            wake.wake();
        }
    }
    fn poll(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.mode.load(Ordering::Acquire) {
            1 => {
                *self.wake.lock().unwrap() = Some(cx.waker().clone());
                // Check after registration, so a concurrent release is not lost.
                if self.mode.load(Ordering::Acquire) == 1 {
                    Poll::Pending
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
            2 => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "synthetic-private-error-body-must-not-appear",
            ))),
            _ => Poll::Ready(Ok(())),
        }
    }
}
struct GatedIo {
    io: tokio::io::DuplexStream,
    gate: Arc<Gate>,
}
impl AsyncRead for GatedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, b)
    }
}
impl AsyncWrite for GatedIo {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, b: &[u8]) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.gate.poll(cx))?;
        Pin::new(&mut this.io).poll_write(cx, b)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        b: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        std::task::ready!(this.gate.poll(cx))?;
        Pin::new(&mut this.io).poll_write_vectored(cx, b)
    }
    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}
type ClientStream =
    tokio_rustls::client::TlsStream<aegis_server::phase_witness::io_progress::ObservedIo<GatedIo>>;
type ServerStream = tokio_rustls::server::TlsStream<
    aegis_server::phase_witness::io_progress::ObservedIo<tokio::io::DuplexStream>,
>;
async fn pair() -> (ClientStream, ServerStream, Arc<Gate>, IoWitness, IoWitness) {
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    let identity = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let ca = directory.path().join("public-ca.pem");
    std::fs::write(&ca, identity.cert.pem()).unwrap();
    let settings = RelaySettings {
        tls_backend: RelayTlsBackend::Rustls,
        ca_cert: Some(ca),
        ..Default::default()
    };
    let connector = rustls_tls_connector_for_settings(&settings, &[b"h2".to_vec()], true).unwrap();
    let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
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
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    cfg.key_log = Arc::new(rustls::NoKeyLog);
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let (c, s) = tokio::io::duplex(64 * 1024);
    let gate = Arc::new(Gate::default());
    let client_wire = IoWitness::default();
    let server_wire = IoWitness::default();
    let (c, s) = tokio::join!(
        connector.connect(
            ServerName::try_from("localhost").unwrap(),
            client_wire.observe(GatedIo {
                io: c,
                gate: gate.clone()
            })
        ),
        acceptor.accept(server_wire.observe(s))
    );
    let (c, s) = (c.unwrap(), s.unwrap());
    require_accepted_ech(&settings, c.get_ref().1.ech_status()).unwrap();
    assert_eq!(
        c.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(c.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    (c, s, gate, client_wire, server_wire)
}
async fn flush_case(error: bool) {
    let (client, mut server, gate, client_wire, server_wire) = pair().await;
    let app = IoWitness::default();
    let mut client = app.observe(client);
    let before = client_wire.snapshot();
    gate.set(1);
    let payload = [0x5a; 434];
    client.write_all(&payload).await.unwrap();
    assert_eq!(app.snapshot().write_bytes, 434);
    assert_eq!(client_wire.snapshot().write_bytes, before.write_bytes);
    // A single real TLS flush poll observes Pending, without waiting a new deadline.
    std::future::poll_fn(|cx| {
        assert!(Pin::new(&mut client).poll_flush(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    let blocked = client_wire.snapshot();
    assert!(blocked.write.pending > before.write.pending);
    assert_eq!(
        blocked.flush.polls, before.flush.polls,
        "TLS encrypted draining has not reached underlying flush"
    );
    assert_eq!(app.snapshot().flush.pending, 1);
    if error {
        gate.set(2);
        assert_eq!(
            client.flush().await.unwrap_err().kind(),
            io::ErrorKind::ConnectionReset
        );
        let metadata = format!("{:?} {:?}", app.snapshot(), client_wire.snapshot());
        assert!(!metadata.contains("synthetic-private-error-body"));
        assert!(client_wire.snapshot().write.errors > before.write.errors);
    } else {
        gate.set(0);
        let send = async {
            client.flush().await.unwrap();
        };
        let read = async {
            let mut received = [0; 434];
            server.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
        };
        tokio::join!(send, read);
        assert_eq!(app.snapshot().write_bytes, 434);
        assert!(client_wire.snapshot().write_bytes > before.write_bytes);
        assert!(server_wire.snapshot().read_bytes > 434);
        assert!(client_wire.snapshot().flush.ready > before.flush.ready);
    }
    drop(client);
    drop(server);
    assert_eq!(app.snapshot().dropped, 1);
    assert_eq!(client_wire.snapshot().dropped, 1);
    assert_eq!(server_wire.snapshot().dropped, 1);
}
#[tokio::test]
async fn actual_tls_buffered_434_is_distinct_from_pending_underlying_encrypted_write() {
    tokio::time::timeout(std::time::Duration::from_secs(10), flush_case(false))
        .await
        .unwrap();
}
#[tokio::test]
async fn actual_tls_underlying_error_keeps_kind_and_never_exposes_private_error_body() {
    tokio::time::timeout(std::time::Duration::from_secs(10), flush_case(true))
        .await
        .unwrap();
}
#[tokio::test]
async fn underlying_vectored_metadata_is_separate_from_total_write_without_payload_logging() {
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let (c, mut s) = tokio::io::duplex(1024);
        let witness = IoWitness::default();
        let mut c = witness.observe(c);
        let secret = b"synthetic-private-bytes";
        let n = c
            .write_vectored(&[IoSlice::new(secret), IoSlice::new(secret)])
            .await
            .unwrap();
        assert!(n > 0);
        let mut received = vec![0; n];
        s.read_exact(&mut received).await.unwrap();
        let observed = witness.snapshot();
        assert_eq!(observed.write_vectored.ready, 1);
        assert_eq!(observed.write_bytes, n as u64);
        assert!(!format!("{observed:?}").contains("synthetic-private-bytes"));
        drop(c);
        assert_eq!(witness.snapshot().dropped, 1);
    })
    .await
    .unwrap();
}
