//! Actual installed server ownership fixture. The H2/inner-device TLS/Open/
//! adaptive codec/target/revocation paths are real; outer H2 uses owned duplex.
//! Common helper plumbing is present in both original-server-body and candidate
//! roles. No native transport or client production cancellation claim is made.
use super::*;
use aegis_core::carrier_runtime::ShapingCleanupOwner;
use std::{
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    task::{Context as TaskContext, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{timeout_at, Instant};

#[derive(Default)]
struct Destruction {
    drops: AtomicUsize,
    permit_held: AtomicBool,
}
struct WatchedCarrier<S> {
    io: S,
    server: Server,
    destruction: Arc<Destruction>,
}
impl<S> Drop for WatchedCarrier<S> {
    fn drop(&mut self) {
        let held = matches!(self.server.try_acquire_session(None), Err(error)
            if error.kind() == io::ErrorKind::WouldBlock);
        self.destruction.permit_held.store(held, Ordering::SeqCst);
        self.destruction.drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for WatchedCarrier<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_read(cx, output)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for WatchedCarrier<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().io).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

struct Tasks(Vec<tokio::task::JoinHandle<anyhow::Result<()>>>);
impl Tasks {
    fn push(&mut self, task: tokio::task::JoinHandle<anyhow::Result<()>>) {
        self.0.push(task);
    }
    async fn abort_and_join_until(&mut self, cutoff: Instant) -> anyhow::Result<()> {
        for task in &self.0 {
            task.abort();
        }
        let mut failure = None;
        // Retain all handles and drain even when one owner fails. No await
        // resets the absolute cutoff; Drop-only abort is never a joined claim.
        for mut task in self.0.drain(..) {
            let result = timeout_at(cutoff, &mut task).await;
            let error = match result {
                Ok(Ok(Ok(()))) => None,
                Ok(Err(error)) if error.is_cancelled() => None,
                Ok(_) => Some(anyhow::anyhow!("fixture direct owner failed")),
                Err(_) => Some(anyhow::anyhow!("fixture direct owner terminal unconfirmed")),
            };
            if failure.is_none() {
                failure = error;
            }
        }
        if Instant::now() >= cutoff && failure.is_none() {
            failure = Some(anyhow::anyhow!("fixture direct cleanup exceeded cutoff"));
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}
struct Returned {
    result: anyhow::Result<()>,
    dropped_before_return: bool,
    permit_held_at_drop: bool,
}
struct Witness {
    returned: Returned,
    target_eof: bool,
    permit_released: bool,
}

#[tokio::test(flavor = "current_thread")]
async fn actual_adaptive_device_tls_h2_revocation_joins_carrier_before_permit_release() {
    use secure_channel::registry::{DeviceRecord, DeviceRegistry, DEFAULT_POLICY_TTL_SECS};
    // Same existing complete profile and ordinary owner envelope; no seed,
    // byte, idle timer, shaping lifetime or mathematical policy changes.
    let profile = research_profiles().remove(2);
    profile.validate().unwrap();
    let training = secure_channel::relay_shaping::ServerTraining::prepare(&profile)
        .await
        .unwrap()
        .unwrap();
    let mut f = fixture(true);
    let registry_path = f._dir.path().join("cleanup-devices.json");
    let now = secure_channel::registry::unix_now().unwrap();
    let registry = DeviceRegistry {
        devices: vec![DeviceRecord {
            device_id: "device-a".into(),
            certificate_sha256: f.server_settings.allowed_client_sha256[0].clone(),
            not_after_unix_secs: now + 3600,
            revoked: false,
        }],
        ..DeviceRegistry::new(now, DEFAULT_POLICY_TTL_SECS).unwrap()
    };
    secure_channel::registry::publish_snapshot(&registry_path, &registry).unwrap();
    f.server_settings.allowed_client_sha256.clear();
    f.server_settings.device_registry = Some(registry_path.clone());
    f.server_settings.handshake_timeout_ms = 3000;
    f.server_settings.idle_timeout_ms = 10_000;
    f.server_settings.admission.max_sessions = 1;
    f.server_settings.admission.max_sessions_per_peer = 1;
    f.server = Server::load(&f.server_settings).unwrap();
    let watcher = f.server.start_registry_watcher().unwrap();
    let client_owner = ShapingCleanupOwner::new();
    let mut tasks = Tasks(Vec::new());
    let destruction = Arc::new(Destruction::default());
    // All direct handles and the watcher live outside the timed operation.
    // Setup errors/body errors/timeout each pass through the same cleanup.
    let operation =
        timeout_at(Instant::now() + Duration::from_secs(15), async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
            let port = listener.local_addr()?.port();
            let (target_done, target_eof) = tokio::sync::oneshot::channel();
            tasks.push(tokio::spawn(async move {
                let (mut target, _) = listener.accept().await?;
                let mut up = [0; 8];
                target.read_exact(&mut up).await?;
                anyhow::ensure!(&up == b"up-mark1", "actual target uplink mismatch");
                target.write_all(b"down-m02").await?;
                let n = target.read(&mut [0; 1]).await?;
                anyhow::ensure!(n == 0, "post-revocation target received extra bytes");
                target_done
                    .send(true)
                    .map_err(|_| anyhow::anyhow!("target receipt owner lost"))?;
                Ok(())
            }));
            let (client_io, server_io) = tokio::io::duplex(64 * 1024);
            let (returned_tx, returned_rx) = tokio::sync::oneshot::channel();
            let server = f.server.clone();
            let server_profile = profile.clone();
            let observer = destruction.clone();
            tasks.push(tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await?;
            let (request, mut respond) = connection.accept().await
                .ok_or_else(|| anyhow::anyhow!("missing actual H2 request"))??;
            anyhow::ensure!(request.method() == http::Method::POST
                && request.uri().path() == secure_channel::GRPC_PATH
                && request.headers().get("content-type").is_some_and(|h| h == "application/grpc"),
                "actual H2 Open envelope mismatch");
            let response = http::Response::builder().status(200)
                .header("content-type", "application/grpc").body(())?;
            let send = respond.send_response(response, false)?;
            let carrier = WatchedCarrier {
                io: GrpcIo::new(H2Stream::new(send, request.into_body())),
                server: server.clone(), destruction: observer.clone(),
            };
            let policy = TargetPolicyConfig {
                profile: crate::config::TargetPolicyProfile::FullVpnEgress,
                ..TargetPolicyConfig::default()
            };
            let limiter = RateLimiter::new(1, 300, true);
            let handling = crate::session::secure::serve_carrier_with_mode(
                carrier, server, &policy, &limiter, None, None, || Ok(()),
                crate::session::secure::PrivacyMode::Relay(Some(&server_profile), Some(&training)),
                None, Default::default(),
            );
            tokio::pin!(handling);
            let mut sender = Some(returned_tx);
            loop {
                tokio::select! {
                    result = &mut handling, if sender.is_some() => {
                        // This observation is in the SAME terminal-return poll,
                        // before scheduling the parent or any other fixture task.
                        let returned = Returned {
                            result,
                            dropped_before_return: observer.drops.load(Ordering::SeqCst) == 1,
                            permit_held_at_drop: observer.permit_held.load(Ordering::SeqCst),
                        };
                        if let Some(tx) = sender.take() { let _ = tx.send(returned); }
                    }
                    next = connection.accept() => match next {
                        Some(Ok(_)) => return Err(anyhow::anyhow!("unexpected second H2 request")),
                        None | Some(Err(_)) if sender.is_none() => return Ok(()),
                        _ => return Err(anyhow::anyhow!("H2 owner ended before server result")),
                    }
                }
            }
        }));
            let (mut requests, connection) = h2::client::handshake(client_io).await?;
            tasks.push(tokio::spawn(async move {
                connection.await?;
                Ok(())
            }));
            let request = http::Request::builder()
                .method(http::Method::POST)
                .uri(secure_channel::GRPC_PATH)
                .header("content-type", "application/grpc")
                .body(())?;
            let (response, send) = requests.send_request(request, false)?;
            let response = response.await?;
            anyhow::ensure!(
                response.status() == 200,
                "actual H2 response status mismatch"
            );
            let carrier = GrpcIo::new(H2Stream::new(send, response.into_body()));
            let inner = f.client.connect(carrier).await?;
            let mut inner = secure_channel::relay_shaping::client_owned(
                inner,
                Some(&profile),
                Instant::now() + Duration::from_secs(3),
                Some(&client_owner),
            )
            .await?;
            secure_channel::write_open(
                &mut inner,
                &secure_channel::OpenRequest {
                    version: 1,
                    transport: secure_channel::Transport::Tcp,
                    host: "127.0.0.1".into(),
                    port,
                },
            )
            .await?;
            anyhow::ensure!(
                inner.read_u8().await? == 0,
                "actual protected Open rejected"
            );
            inner.write_all(b"up-mark1").await?;
            inner.flush().await?;
            let mut down = [0; 8];
            inner.read_exact(&mut down).await?;
            anyhow::ensure!(
                &down == b"down-m02",
                "actual authenticated downlink mismatch"
            );
            anyhow::ensure!(
                matches!(f.server.try_acquire_session(None), Err(error)
            if error.kind() == io::ErrorKind::WouldBlock),
                "actual active permit not held"
            );
            let (published_tx, published_rx) = tokio::sync::oneshot::channel();
            let publication_owner = f._dir.clone();
            tasks.push(tokio::task::spawn_blocking(move || {
                let _private_files = publication_owner;
                crate::devices::revoke(&registry_path, "device-a")?;
                published_tx
                    .send(())
                    .map_err(|_| anyhow::anyhow!("revocation publication owner lost"))?;
                Ok(())
            }));
            published_rx.await?;
            let returned = returned_rx.await?;
            anyhow::ensure!(
                inner.read_u8().await.is_err(),
                "revoked client accepted later payload"
            );
            let target_eof = target_eof.await?;
            let permit_released = f.server.try_acquire_session(None).is_ok();
            Ok::<_, anyhow::Error>(Witness {
                returned,
                target_eof,
                permit_released,
            })
        })
        .await;
    // Independent finite cleanup, no graceful post-revocation drain. None of
    // these awaits changes the original operation/session/record clocks.
    let cleanup_cutoff = Instant::now() + Duration::from_secs(2);
    for task in &tasks.0 {
        task.abort();
    }
    let client_cleanup = client_owner.cancel_and_join_until(cleanup_cutoff).await;
    let direct_cleanup = tasks.abort_and_join_until(cleanup_cutoff).await;
    let watcher_cleanup = watcher.stop_and_join_until(cleanup_cutoff).await;
    // Accumulate/drain all three categories before any final assertion.
    let client_cleanup = client_cleanup.expect("fixture client worker terminal unconfirmed");
    direct_cleanup.expect("fixture direct owners terminal unconfirmed");
    watcher_cleanup
        .expect("fixture watcher terminal unconfirmed; nested blocking read is not covered");
    let witness = operation
        .expect("original fixture workload cutoff")
        .expect("actual fixture precondition failed");
    let error = witness
        .returned
        .result
        .expect_err("revocation must remain a failure");
    let revoked = matches!(
        error
            .downcast_ref::<io::Error>()
            .and_then(secure_channel::AuthenticationFailure::from_io),
        Some(secure_channel::AuthenticationFailure::DeviceNotAllowed)
    );
    eprintln!("P2_SERVER_TERMINAL revoked={revoked} dropped_before_return={} permit_held_at_drop={} permit_released={} target_eof={}",
        witness.returned.dropped_before_return, witness.returned.permit_held_at_drop,
        witness.permit_released, witness.target_eof);
    assert_eq!((client_cleanup.registered, client_cleanup.joined), (1, 1));
    assert!(revoked, "original typed revocation error must remain");
    assert!(witness.target_eof && witness.permit_released);
    assert!(
        witness.returned.dropped_before_return,
        "server returned before actual shaping carrier destruction"
    );
    assert!(
        witness.returned.permit_held_at_drop,
        "server released permit before actual shaping carrier destruction"
    );
}
