use super::*;
use aegis_core::tunnel::{open_tunnel_response, seal_tunnel_request, TunnelRequest, TunnelStatus};
use anyhow::Context as _;
use bytes::Bytes;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::io;
use std::pin::Pin;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

const AUTH: &[u8] = b"7f0bfd1d31eade038cc6d5581467707af913a1a43e16d7cad86894b3e2a9721e";
const UP: &[u8] = b"server-h2-coop-up-marker";
const DOWN: &[u8; 128] = &[0x42; 128];

fn grpc_frame(payload: &[u8]) -> Bytes {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.push(0);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    Bytes::from(frame)
}

async fn read_grpc(
    body: &mut h2::RecvStream,
    pending: &mut Vec<u8>,
) -> anyhow::Result<Option<Vec<u8>>> {
    loop {
        if pending.len() >= 5 {
            anyhow::ensure!(pending[0] == 0, "compressed fixture message");
            let len = u32::from_be_bytes(pending[1..5].try_into().unwrap()) as usize;
            anyhow::ensure!(len <= MAX_GRPC_MESSAGE_BYTES, "unbounded fixture frame");
            if pending.len() >= len + 5 {
                let payload = pending[5..5 + len].to_vec();
                pending.drain(..5 + len);
                return Ok(Some(payload));
            }
        }
        let Some(chunk) = body.data().await.transpose()? else {
            anyhow::ensure!(pending.is_empty(), "truncated fixture frame");
            return Ok(None);
        };
        body.flow_control().release_capacity(chunk.len())?;
        pending.extend_from_slice(&chunk);
    }
}

struct ExhaustAfterValidated {
    inner: TcpStream,
    witness: crate::phase_witness::ServerPhaseWitness,
    injected: Arc<AtomicUsize>,
    awaiting_fresh_write: Arc<AtomicBool>,
}

impl AsyncRead for ExhaustAfterValidated {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let validated = self.witness.snapshot()
            [crate::phase_witness::ServerPhase::GrpcOpenValidated as usize]
            .observations
            == 1;
        if validated && self.awaiting_fresh_write.load(Ordering::Acquire) {
            self.injected.fetch_add(1, Ordering::AcqRel);
            while let Poll::Ready(permit) = tokio::task::coop::poll_proceed(cx) {
                permit.made_progress();
            }
            return Poll::Pending;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for ExhaustAfterValidated {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // This controlled transport models the measured Windows boundary:
        // writes cannot progress in the poll whose read consumed the budget.
        if !tokio::task::coop::has_budget_remaining() {
            return Poll::Pending;
        }
        if self.injected.load(Ordering::Acquire) > 0 {
            self.awaiting_fresh_write.store(false, Ordering::Release);
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if !tokio::task::coop::has_budget_remaining() {
            return Poll::Pending;
        }
        if self.injected.load(Ordering::Acquire) > 0 {
            self.awaiting_fresh_write.store(false, Ordering::Release);
        }
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !tokio::task::coop::has_budget_remaining() {
            return Poll::Pending;
        }
        if self.injected.load(Ordering::Acquire) > 0 {
            self.awaiting_fresh_write.store(false, Ordering::Release);
        }
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn actual_tls_h2_authenticated_open_flushes_after_exhausted_receive_turn() {
    let mut owners = tokio::task::JoinSet::new();
    let mut request_owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
    let request_registry = request_owner.registry();
    let witness = crate::phase_witness::ServerPhaseWitness::default();
    let injected = Arc::new(AtomicUsize::new(0));
    let awaiting_fresh_write = Arc::new(AtomicBool::new(true));
    let phase: Result<anyhow::Result<()>, tokio::time::error::Elapsed> =
        tokio::time::timeout(Duration::from_secs(20), async {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let CertifiedKey { cert, key_pair } =
                generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let cert_path = dir.path().join("server.pem");
            let key_path = dir.path().join("server.key");
            std::fs::write(&cert_path, cert.pem()).unwrap();
            #[cfg(windows)]
            aegis_core::windows_file::write_private_new(
                &key_path,
                key_pair.serialize_pem().as_bytes(),
                false,
            )
            .unwrap();
            #[cfg(not(windows))]
            {
                std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                        .unwrap();
                }
            }

            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert.der().clone()).unwrap();
            let mut client_tls = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            client_tls.alpn_protocols = vec![b"h2".to_vec()];
            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls));

            let cfg = crate::config::ServerConfig {
                listen: "127.0.0.1:0".into(),
                cert: cert_path,
                key: key_path,
                auth_token: String::from_utf8(AUTH.to_vec()).unwrap(),
                legacy_auth_tokens: Vec::new(),
                process_alias: None,
                logging: Default::default(),
                fallback: "close".into(),
                limits: Default::default(),
                rate_limit: Default::default(),
                target_policy: crate::config::TargetPolicyConfig {
                    profile: crate::config::TargetPolicyProfile::FullVpnEgress,
                    allowed_ports: Vec::new(),
                },
                transport: Default::default(),
                bundle_endpoint: Default::default(),
            };
            let grpc_path = cfg.transport.grpc_path.clone();
            let keyring = TunnelAuthKeyring::from_config(&cfg).unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(
                crate::tls::load_server_config(&cfg.cert, &cfg.key).unwrap(),
            );
            let ingress = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let ingress_addr = ingress.local_addr().unwrap();
            let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_addr = target.local_addr().unwrap();
            let server_witness = witness.clone();
            let server_injected = injected.clone();
            let server_awaiting_fresh_write = awaiting_fresh_write.clone();
            owners.spawn(async move {
                let (tcp, _) = ingress.accept().await?;
                let tls = acceptor
                    .accept(ExhaustAfterValidated {
                        inner: tcp,
                        witness: server_witness.clone(),
                        injected: server_injected,
                        awaiting_fresh_write: server_awaiting_fresh_write,
                    })
                    .await?;
                let result = crate::session::handle_tls_session(
                    tls,
                    &keyring,
                    "close",
                    &crate::config::ServerLimits::default(),
                    &cfg.transport,
                    &cfg.target_policy,
                    &RateLimiter::new(8, 60, false),
                    "127.0.0.1:1".parse().unwrap(),
                    None,
                    &request_registry,
                    Some(&server_witness),
                    super::super::AdmissionBudget::new(Duration::from_secs(20)),
                )
                .await;
                result
            });
            owners.spawn(async move {
                let (mut stream, _) = target.accept().await?;
                let mut up = vec![0; UP.len()];
                stream.read_exact(&mut up).await?;
                anyhow::ensure!(up == UP, "upload marker changed");
                stream.write_all(DOWN).await?;
                stream.shutdown().await?;
                anyhow::Ok(())
            });

            let tcp = TcpStream::connect(ingress_addr).await?;
            let tls = connector
                .connect("localhost".try_into().unwrap(), tcp)
                .await?;
            let mut h2_builder = h2::client::Builder::new();
            h2_builder.initial_window_size(32);
            let (mut sender, connection) = h2_builder.handshake(tls).await?;
            owners.spawn(async move { connection.await.map_err(Into::into) });
            let request = http::Request::builder()
                .method("POST")
                .uri(grpc_path)
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(())?;
            let (response, mut send) = sender.send_request(request, false)?;
            let open = seal_tunnel_request(
                &TunnelRequest {
                    host: "127.0.0.1".into(),
                    port: target_addr.port(),
                },
                AUTH,
            )?;
            send.send_data(grpc_frame(&open), false)?;
            let response = response.await?;
            anyhow::ensure!(response.status().is_success(), "response headers missing");
            let mut receive = response.into_body();
            let mut pending = Vec::new();
            let sealed_ack = read_grpc(&mut receive, &mut pending)
                .await?
                .context("ACK missing")?;
            let ack = open_tunnel_response(&sealed_ack, AUTH)?;
            anyhow::ensure!(ack.status == TunnelStatus::Ok, "authenticated ACK refused");
            send.send_data(grpc_frame(UP), true)?;
            let mut downlink = Vec::new();
            while let Some(payload) = read_grpc(&mut receive, &mut pending).await? {
                anyhow::ensure!(
                    downlink.len() + payload.len() <= DOWN.len(),
                    "excess downlink"
                );
                downlink.extend_from_slice(&payload);
            }
            anyhow::ensure!(downlink == DOWN.as_slice(), "downlink marker changed");
            anyhow::ensure!(injected.load(Ordering::Acquire) >= 1, "fault not injected");
            anyhow::ensure!(
                !awaiting_fresh_write.load(Ordering::Acquire),
                "fresh write turn not observed"
            );
            let phases = witness.snapshot();
            anyhow::ensure!(
                phases[crate::phase_witness::ServerPhase::GrpcOpenValidated as usize].observations
                    == 1,
                "validated OPEN count changed"
            );
            anyhow::ensure!(
                phases[crate::phase_witness::ServerPhase::GrpcResponseHeadersQueued as usize]
                    .observations
                    == 1,
                "queued response count changed"
            );
            anyhow::ensure!(
                phases[crate::phase_witness::ServerPhase::TargetDialStarted as usize].observations
                    == 1,
                "target dial count changed"
            );
            anyhow::Ok(())
        })
        .await;

    owners.abort_all();
    let cleanup = tokio::time::timeout(Duration::from_secs(1), async {
        let mut task_failure = None;
        while let Some(joined) = owners.join_next().await {
            match joined {
                Ok(Err(error)) if task_failure.is_none() => task_failure = Some(error),
                Err(error) if !error.is_cancelled() && task_failure.is_none() => {
                    task_failure = Some(anyhow::anyhow!("owned fixture task panicked"));
                }
                _ => {}
            }
        }
        request_owner.shutdown().await;
        task_failure.map_or(Ok(()), Err)
    })
    .await;

    let phases = witness.snapshot();
    eprintln!(
        "h2_coop_fixture validated={} headers_queued={} target_dial={} injected={} awaiting_fresh_write={}",
        phases[crate::phase_witness::ServerPhase::GrpcOpenValidated as usize].observations,
        phases[crate::phase_witness::ServerPhase::GrpcResponseHeadersQueued as usize].observations,
        phases[crate::phase_witness::ServerPhase::TargetDialStarted as usize].observations,
        injected.load(Ordering::Acquire),
        awaiting_fresh_write.load(Ordering::Acquire),
    );

    phase
        .expect("single unchanged 20-second fixture watchdog")
        .expect("actual TLS/H2 fairness exchange");
    cleanup
        .expect("bounded fixture cleanup")
        .expect("owned fixture tasks completed without error");
}
