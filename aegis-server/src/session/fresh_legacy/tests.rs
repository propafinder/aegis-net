//! Feature-selected server dispatcher, in-memory streams, no external resolver.
use super::*;
use aegis_core::tunnel::fresh_legacy::exchange_raw;
use aegis_core::tunnel::{
    encode_stream_frame, read_stream_frame, seal_tunnel_request, TunnelRequest,
    MAX_TUNNEL_CONTROL_FRAME,
};
use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const CURRENT: &[u8] = b"synthetic-current-audit9-key";
const MIGRATION: &[u8] = b"synthetic-migration-audit9-key";

fn keyring() -> TunnelAuthKeyring {
    TunnelAuthKeyring {
        keys: vec![
            TunnelAuthKey {
                id: Arc::from("synthetic-current"),
                secret: Arc::from(CURRENT),
                legacy: false,
                not_after_unix_secs: None,
            },
            TunnelAuthKey {
                id: Arc::from("synthetic-migration"),
                secret: Arc::from(MIGRATION),
                legacy: true,
                not_after_unix_secs: Some(super::super::unix_time_now() + 60),
            },
        ]
        .into(),
        operational_log: Default::default(),
        inner_tls: None,
        https_bridge: None,
        fronted_origin: None,
        relay_training: None,
    }
}

fn request() -> TunnelRequest {
    TunnelRequest {
        host: "target.invalid".into(),
        port: 0,
    }
}
fn peer() -> SocketAddr {
    "192.0.2.9:49909".parse().unwrap()
}

#[tokio::test]
async fn selected_handler_preserves_port_zero_policy_and_matched_migration_final() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let keys = keyring();
    let limits = ServerLimits::default();
    let policy = TargetPolicyConfig::default();
    let rate = RateLimiter::new(8, 60, false);
    let limiter = super::super::admission::SocketAdmissionLimiter::new(1);
    let budget = AdmissionBudget::new(Duration::from_secs(2))
        .with_socket_permit(limiter.try_acquire(peer().ip()).unwrap());
    let deadline = budget.deadline;
    let request = request();
    // The production resolve-once policy rejects port zero before any DNS/dial.
    let client_future = exchange_raw(&mut client, &request, MIGRATION, deadline);
    let server_future = super::super::handle_legacy_stream_session_with_admission(
        &mut server,
        &keys,
        "proxy:127.0.0.1:1",
        &limits,
        &policy,
        &rate,
        peer(),
        budget,
    );
    let (response, result) = tokio::join!(client_future, server_future);
    result.unwrap();
    assert_eq!(response.unwrap().status, TunnelStatus::BadTarget);
    assert!(
        limiter.try_acquire(peer().ip()).is_some(),
        "valid proof releases setup slot"
    );
}

#[tokio::test]
async fn selected_handler_rejects_v3_without_decoy_proxy_or_acceptance() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let keys = keyring();
    let limits = ServerLimits::default();
    let policy = TargetPolicyConfig::default();
    let rate = RateLimiter::new(8, 60, false);
    let budget = AdmissionBudget::new(Duration::from_secs(2));
    let deadline = budget.deadline;
    let v3 = seal_tunnel_request(&request(), CURRENT).unwrap();
    client.write_all(&encode_stream_frame(&v3)).await.unwrap();
    super::super::handle_legacy_stream_session_with_admission(
        &mut server,
        &keys,
        "proxy:127.0.0.1:1",
        &limits,
        &policy,
        &rate,
        peer(),
        budget,
    )
    .await
    .unwrap();
    drop(server);
    let mut response = Vec::new();
    tokio::time::timeout_at(deadline, client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(
        response.is_empty(),
        "feature path returns neither v3 acceptance nor decoy bytes"
    );
}

#[tokio::test(start_paused = true)]
async fn selected_handler_retains_setup_slot_until_pending_proof_deadline_then_releases_it() {
    let (mut client, mut server) = tokio::io::duplex(4096);
    let keys = keyring();
    let limits = ServerLimits::default();
    let policy = TargetPolicyConfig::default();
    let rate = RateLimiter::new(8, 60, false);
    let limiter = super::super::admission::SocketAdmissionLimiter::new(1);
    let budget = AdmissionBudget::new(Duration::from_secs(1))
        .with_socket_permit(limiter.try_acquire(peer().ip()).unwrap());
    let original_deadline = budget.deadline;
    let (open, _) =
        aegis_core::tunnel::fresh_legacy::ClientOpen::start(&request(), CURRENT).unwrap();
    client.write_all(&encode_stream_frame(&open)).await.unwrap();
    let handling = super::super::handle_legacy_stream_session_with_admission(
        &mut server,
        &keys,
        "close",
        &limits,
        &policy,
        &rate,
        peer(),
        budget,
    );
    tokio::pin!(handling);
    std::future::poll_fn(|cx| {
        assert!(handling.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    let challenge = read_stream_frame(&mut client, MAX_TUNNEL_CONTROL_FRAME)
        .await
        .unwrap();
    assert!(!challenge.is_empty());
    assert!(
        limiter.try_acquire(peer().ip()).is_none(),
        "Open alone is not admission"
    );
    tokio::time::advance(Duration::from_secs(1)).await;
    let error = handling.await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(Instant::now(), original_deadline);
    assert!(
        limiter.try_acquire(peer().ip()).is_some(),
        "failed proof owner reclaims setup slot"
    );
}

#[tokio::test]
async fn existing_credential_expiry_can_only_narrow_setup_deadline() {
    let mut key = keyring().keys[1].clone();
    key.not_after_unix_secs = Some(super::super::unix_time_now().saturating_sub(1));
    assert!(expiry_deadline(&key).unwrap() <= Instant::now());
    key.not_after_unix_secs = None;
    assert!(expiry_deadline(&key).is_none());
}

struct FinalBlockedOutput {
    inner: tokio::io::DuplexStream,
    block: Arc<std::sync::atomic::AtomicBool>,
    blocked_writes: Arc<std::sync::atomic::AtomicUsize>,
}
impl AsyncRead for FinalBlockedOutput {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for FinalBlockedOutput {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        if self.block.load(std::sync::atomic::Ordering::SeqCst) {
            self.blocked_writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
struct OwnedTask<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[tokio::test(start_paused = true)]
async fn selected_handler_bounds_blocked_bound_policy_final_with_existing_write_budget() {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (mut client, server) = tokio::io::duplex(4096);
    let block = Arc::new(AtomicBool::new(false));
    let blocked_writes = Arc::new(AtomicUsize::new(0));
    let mut server = FinalBlockedOutput {
        inner: server,
        block: block.clone(),
        blocked_writes: blocked_writes.clone(),
    };
    let keys = keyring();
    let limits = ServerLimits {
        write_timeout_ms: 100,
        ..ServerLimits::default()
    };
    let limiter = super::super::admission::SocketAdmissionLimiter::new(1);
    let budget = AdmissionBudget::new(Duration::from_secs(1))
        .with_socket_permit(limiter.try_acquire(peer().ip()).unwrap());
    let original_cutoff = budget.deadline;
    let mut task = OwnedTask(tokio::spawn(async move {
        super::super::handle_legacy_stream_session_with_admission(
            &mut server,
            &keys,
            "proxy:127.0.0.1:1",
            &limits,
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            peer(),
            budget,
        )
        .await
    }));
    // The actual challenge is written before output blocks. Port zero remains
    // the existing target-policy denial before any resolver or target dial.
    let (open, context) =
        aegis_core::tunnel::fresh_legacy::ClientOpen::start(&request(), CURRENT).unwrap();
    client.write_all(&encode_stream_frame(&open)).await.unwrap();
    let challenge = tokio::time::timeout_at(
        original_cutoff,
        read_stream_frame(&mut client, MAX_TUNNEL_CONTROL_FRAME),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        limiter.try_acquire(peer().ip()).is_none(),
        "Open retains setup slot"
    );
    let (proof, _bound_final_context) = context.prove(&challenge).unwrap();
    block.store(true, Ordering::SeqCst);
    client
        .write_all(&encode_stream_frame(&proof))
        .await
        .unwrap();
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
    assert!(
        blocked_writes.load(Ordering::SeqCst) > 0,
        "actual valid-proof Final reached blocked output"
    );
    assert!(
        limiter.try_acquire(peer().ip()).is_some(),
        "valid proof releases setup slot"
    );
    let final_start = Instant::now();
    assert!(final_start < original_cutoff);
    tokio::time::advance(Duration::from_millis(99)).await;
    assert!(!task.0.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    let error = tokio::time::timeout(Duration::from_secs(1), &mut task.0)
        .await
        .expect("finite actual handler fixture watchdog")
        .expect("actual handler task")
        .unwrap_err();
    assert_eq!(
        error.downcast_ref::<std::io::Error>().unwrap().kind(),
        std::io::ErrorKind::TimedOut
    );
    assert_eq!(Instant::now(), final_start + Duration::from_millis(100));
    assert!(
        Instant::now() < original_cutoff,
        "write budget narrows original admission budget"
    );
}
