//! Finite in-memory fixtures for row 52. No sockets, credentials or load loops.
use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

struct OwnedTask<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Dropped<T> {
    inner: T,
    dropped: Arc<AtomicUsize>,
}
impl<T> Drop for Dropped<T> {
    fn drop(&mut self) {
        self.dropped.fetch_add(1, Ordering::SeqCst);
    }
}
impl<T: AsyncRead + Unpin> AsyncRead for Dropped<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<T: AsyncWrite + Unpin> AsyncWrite for Dropped<T> {
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

async fn settle() {
    tokio::task::yield_now().await;
    tokio::task::yield_now().await;
}

async fn finish<T>(task: &mut OwnedTask<T>) -> T {
    tokio::time::timeout(Duration::from_secs(1), &mut task.0)
        .await
        .expect("finite fixture watchdog")
        .expect("forwarding task")
}

#[tokio::test(start_paused = true)]
async fn establishment_deadline_cancels_the_entire_pending_owner() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let owner = Dropped {
        inner: (),
        dropped: dropped.clone(),
    };
    let mut task = OwnedTask(tokio::spawn(async move {
        establish(
            async move {
                let _owner = owner;
                std::future::pending::<io::Result<()>>().await
            },
            Duration::from_millis(100),
        )
        .await
    }));
    settle().await;
    tokio::time::advance(Duration::from_millis(99)).await;
    assert!(!task.0.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(
        finish(&mut task).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn control_write_has_one_deadline_even_with_partial_progress() {
    let (mut server, mut peer) = tokio::io::duplex(1);
    let mut task = OwnedTask(tokio::spawn(async move {
        write_control(
            async { server.write_all(b"abcd").await.map_err(anyhow::Error::from) },
            Duration::from_millis(100),
        )
        .await
    }));
    settle().await;
    for _ in 0..2 {
        tokio::time::advance(Duration::from_millis(40)).await;
        let mut byte = [0];
        peer.read_exact(&mut byte).await.unwrap();
        settle().await;
    }
    assert!(!task.0.is_finished());
    tokio::time::advance(Duration::from_millis(20)).await;
    let error = finish(&mut task).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::TimedOut
    );
}

#[tokio::test(start_paused = true)]
async fn silent_idle_releases_owned_streams_and_connection_permit() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let (_client_peer, client) = tokio::io::duplex(64);
    let (_target_peer, target) = tokio::io::duplex(64);
    let mut client = Dropped {
        inner: client,
        dropped: dropped.clone(),
    };
    let mut target = Dropped {
        inner: target,
        dropped: dropped.clone(),
    };
    let mut task = OwnedTask(tokio::spawn(async move {
        let _permit = permit;
        forward(
            &mut client,
            &mut target,
            Duration::from_millis(100),
            Duration::from_millis(500),
        )
        .await
    }));
    settle().await;
    assert_eq!(slots.available_permits(), 0);
    tokio::time::advance(Duration::from_millis(99)).await;
    assert!(!task.0.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    assert_eq!(
        finish(&mut task).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(slots.available_permits(), 1);
}

#[tokio::test(start_paused = true)]
async fn active_asymmetric_long_session_and_reverse_half_close_are_preserved() {
    let (mut client_peer, mut client) = tokio::io::duplex(64);
    let (mut target_peer, mut target) = tokio::io::duplex(64);
    let mut task = OwnedTask(tokio::spawn(async move {
        forward(
            &mut client,
            &mut target,
            Duration::from_millis(100),
            Duration::from_millis(50),
        )
        .await
    }));
    settle().await;
    for _ in 0..5 {
        tokio::time::advance(Duration::from_millis(80)).await;
        client_peer.write_all(b"request").await.unwrap();
        let mut bytes = [0; 7];
        tokio::time::timeout(Duration::from_secs(1), target_peer.read_exact(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes, b"request");
        assert!(!task.0.is_finished());
    }
    // Five idle periods elapsed in total, but bytes in one direction retain
    // the whole authorized session; the quiet direction has no read deadline.
    client_peer.shutdown().await.unwrap();
    let mut eof = [0];
    assert_eq!(target_peer.read(&mut eof).await.unwrap(), 0);
    target_peer.write_all(b"response").await.unwrap();
    let mut response = [0; 8];
    client_peer.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"response");
    target_peer.shutdown().await.unwrap();
    assert_eq!(finish(&mut task).await.unwrap(), (35, 8));
}

#[tokio::test(start_paused = true)]
async fn opposite_direction_activity_cannot_extend_a_stalled_write() {
    let (mut client_peer, mut client) = tokio::io::duplex(64);
    let (mut target_peer, mut target) = tokio::io::duplex(1);
    let mut task = OwnedTask(tokio::spawn(async move {
        forward(
            &mut client,
            &mut target,
            Duration::from_secs(1),
            Duration::from_millis(100),
        )
        .await
    }));
    client_peer.write_all(&[7; 32]).await.unwrap();
    settle().await;
    for _ in 0..3 {
        tokio::time::advance(Duration::from_millis(25)).await;
        target_peer.write_all(b"r").await.unwrap();
        let mut reply = [0];
        tokio::time::timeout(Duration::from_secs(1), client_peer.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"r");
        settle().await;
        assert!(!task.0.is_finished());
    }
    tokio::time::advance(Duration::from_millis(25)).await;
    assert_eq!(
        finish(&mut task).await.unwrap_err().kind(),
        io::ErrorKind::TimedOut
    );
}

struct PendingClose {
    inner: DuplexStream,
    pending_flush: bool,
}
impl AsyncRead for PendingClose {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for PendingClose {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_flush {
            Poll::Pending
        } else {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[tokio::test(start_paused = true)]
async fn flush_and_half_close_cannot_hold_the_owner_forever() {
    for pending_flush in [false, true] {
        let (mut client_peer, mut client) = tokio::io::duplex(64);
        let (_target_peer, target) = tokio::io::duplex(64);
        let mut target = PendingClose {
            inner: target,
            pending_flush,
        };
        let mut task = OwnedTask(tokio::spawn(async move {
            forward(
                &mut client,
                &mut target,
                Duration::from_secs(1),
                Duration::from_millis(100),
            )
            .await
        }));
        client_peer.shutdown().await.unwrap();
        settle().await;
        tokio::time::advance(Duration::from_millis(100)).await;
        assert_eq!(
            finish(&mut task).await.unwrap_err().kind(),
            io::ErrorKind::TimedOut
        );
    }
}

#[tokio::test(start_paused = true)]
async fn cancellation_drops_owned_streams_and_permit_without_detached_copy_tasks() {
    let dropped = Arc::new(AtomicUsize::new(0));
    let slots = Arc::new(tokio::sync::Semaphore::new(1));
    let permit = slots.clone().acquire_owned().await.unwrap();
    let (_client_peer, client) = tokio::io::duplex(64);
    let (_target_peer, target) = tokio::io::duplex(64);
    let mut client = Dropped {
        inner: client,
        dropped: dropped.clone(),
    };
    let mut target = Dropped {
        inner: target,
        dropped: dropped.clone(),
    };
    let mut task = OwnedTask(tokio::spawn(async move {
        let _permit = permit;
        forward(
            &mut client,
            &mut target,
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .await
    }));
    settle().await;
    task.0.abort();
    assert!(tokio::time::timeout(Duration::from_secs(1), &mut task.0)
        .await
        .unwrap()
        .unwrap_err()
        .is_cancelled());
    assert_eq!(dropped.load(Ordering::SeqCst), 2);
    assert_eq!(slots.available_permits(), 1);
}

#[cfg(not(feature = "legacy-challenge-v1"))]
struct BlockedOutput(DuplexStream);
#[cfg(not(feature = "legacy-challenge-v1"))]
impl AsyncRead for BlockedOutput {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}
#[cfg(not(feature = "legacy-challenge-v1"))]
impl AsyncWrite for BlockedOutput {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

#[cfg(not(feature = "legacy-challenge-v1"))]
#[tokio::test(start_paused = true)]
async fn actual_legacy_handler_bounds_blocked_encrypted_policy_error_response() {
    use super::super::{
        handle_legacy_stream_session_with_admission, AdmissionBudget, TunnelAuthKey,
        TunnelAuthKeyring,
    };
    use crate::config::{ServerLimits, TargetPolicyConfig};
    use crate::rate_limit::RateLimiter;
    use aegis_core::tunnel::{encode_stream_frame, seal_tunnel_request, TunnelRequest};

    const SYNTHETIC: &[u8] = b"synthetic-row52-current-key";
    let keyring = TunnelAuthKeyring {
        keys: vec![TunnelAuthKey {
            id: Arc::from("synthetic-row52"),
            secret: Arc::from(SYNTHETIC),
            legacy: false,
            not_after_unix_secs: None,
        }]
        .into(),
        operational_log: Default::default(),
        inner_tls: None,
        https_bridge: None,
        fronted_origin: None,
        relay_training: None,
    };
    let limits = ServerLimits {
        write_timeout_ms: 100,
        ..ServerLimits::default()
    };
    let (mut client, server) = tokio::io::duplex(4096);
    let mut server = BlockedOutput(server);
    let mut task = OwnedTask(tokio::spawn(async move {
        handle_legacy_stream_session_with_admission(
            &mut server,
            &keyring,
            "close",
            &limits,
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.52:49052".parse().unwrap(),
            AdmissionBudget::new(Duration::from_secs(1)),
        )
        .await
    }));
    // Port zero is denied before name resolution or target connection.
    let request = seal_tunnel_request(
        &TunnelRequest {
            host: "synthetic.invalid".into(),
            port: 0,
        },
        SYNTHETIC,
    )
    .unwrap();
    client
        .write_all(&encode_stream_frame(&request))
        .await
        .unwrap();
    settle().await;
    tokio::time::advance(Duration::from_millis(99)).await;
    assert!(!task.0.is_finished());
    tokio::time::advance(Duration::from_millis(1)).await;
    let error = finish(&mut task).await.unwrap_err();
    assert_eq!(
        error.downcast_ref::<io::Error>().unwrap().kind(),
        io::ErrorKind::TimedOut
    );
}

fn poll_once<F: Future>(future: Pin<&mut F>) -> Poll<F::Output> {
    let waker = futures::task::noop_waker();
    future.poll(&mut Context::from_waker(&waker))
}

#[tokio::test(start_paused = true)]
async fn expired_establishment_refuses_late_ready_success_without_repolling_owner() {
    use std::sync::atomic::AtomicBool;
    let ready = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let operation = std::future::poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        if ready.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    });
    let mut owner = Box::pin(establish(operation, Duration::from_millis(100)));
    assert!(poll_once(owner.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(101)).await;
    ready.store(true, Ordering::SeqCst);
    match poll_once(owner.as_mut()) {
        Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
        _ => panic!("expired establishment must refuse late readiness"),
    }
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn expired_control_write_refuses_late_ready_success_without_repolling_owner() {
    use std::sync::atomic::AtomicBool;
    let ready = Arc::new(AtomicBool::new(false));
    let polls = Arc::new(AtomicUsize::new(0));
    let operation = std::future::poll_fn(|_| {
        polls.fetch_add(1, Ordering::SeqCst);
        if ready.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    });
    let mut owner = Box::pin(write_control(operation, Duration::from_millis(100)));
    assert!(poll_once(owner.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(101)).await;
    ready.store(true, Ordering::SeqCst);
    match poll_once(owner.as_mut()) {
        Poll::Ready(Err(error)) => assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::TimedOut
        ),
        _ => panic!("expired control write must refuse late readiness"),
    }
    assert_eq!(polls.load(Ordering::SeqCst), 1);
}

/// A single optional read byte or EOF, plus explicit endpoint readiness flags.
/// Manual owner polling prevents Tokio from observing expiry before late Ready
/// is introduced; these are finite scheduler-order controls, not traffic loops.
struct ReadinessIo {
    read_mode: Arc<std::sync::atomic::AtomicU8>,
    write_ready: Arc<std::sync::atomic::AtomicBool>,
    flush_ready: Arc<std::sync::atomic::AtomicBool>,
    shutdown_ready: Arc<std::sync::atomic::AtomicBool>,
    write_polls: Arc<AtomicUsize>,
    flush_polls: Arc<AtomicUsize>,
    shutdown_polls: Arc<AtomicUsize>,
}

impl ReadinessIo {
    fn quiet() -> Self {
        use std::sync::atomic::{AtomicBool, AtomicU8};
        Self {
            read_mode: Arc::new(AtomicU8::new(0)),
            write_ready: Arc::new(AtomicBool::new(true)),
            flush_ready: Arc::new(AtomicBool::new(true)),
            shutdown_ready: Arc::new(AtomicBool::new(true)),
            write_polls: Arc::new(AtomicUsize::new(0)),
            flush_polls: Arc::new(AtomicUsize::new(0)),
            shutdown_polls: Arc::new(AtomicUsize::new(0)),
        }
    }
}

impl AsyncRead for ReadinessIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.read_mode.load(Ordering::SeqCst) {
            2 => Poll::Ready(Ok(())),
            1 if buf.remaining() > 0 => {
                self.read_mode.store(0, Ordering::SeqCst);
                buf.put_slice(b"x");
                Poll::Ready(Ok(()))
            }
            _ => Poll::Pending,
        }
    }
}

impl AsyncWrite for ReadinessIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_polls.fetch_add(1, Ordering::SeqCst);
        if self.write_ready.load(Ordering::SeqCst) {
            Poll::Ready(Ok(buf.len()))
        } else {
            Poll::Pending
        }
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flush_polls.fetch_add(1, Ordering::SeqCst);
        if self.flush_ready.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shutdown_polls.fetch_add(1, Ordering::SeqCst);
        if self.shutdown_ready.load(Ordering::SeqCst) {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[tokio::test(start_paused = true)]
async fn expired_stalled_write_flush_and_shutdown_refuse_late_ready_before_inner_io() {
    for operation in ["write", "flush", "shutdown"] {
        let mut client = ReadinessIo::quiet();
        let mut target = ReadinessIo::quiet();
        let (ready, polls) = match operation {
            "write" => {
                client.read_mode.store(1, Ordering::SeqCst);
                target.write_ready.store(false, Ordering::SeqCst);
                (target.write_ready.clone(), target.write_polls.clone())
            }
            "flush" => {
                client.read_mode.store(1, Ordering::SeqCst);
                target.flush_ready.store(false, Ordering::SeqCst);
                (target.flush_ready.clone(), target.flush_polls.clone())
            }
            _ => {
                client.read_mode.store(2, Ordering::SeqCst);
                target.shutdown_ready.store(false, Ordering::SeqCst);
                (target.shutdown_ready.clone(), target.shutdown_polls.clone())
            }
        };
        let mut owner = Box::pin(forward(
            &mut client,
            &mut target,
            Duration::from_secs(1),
            Duration::from_millis(100),
        ));
        assert!(poll_once(owner.as_mut()).is_pending());
        let before = polls.load(Ordering::SeqCst);
        assert!(before > 0, "original {operation} was actually pending");
        tokio::time::advance(Duration::from_millis(101)).await;
        ready.store(true, Ordering::SeqCst);
        match poll_once(owner.as_mut()) {
            Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
            _ => panic!("expired {operation} must refuse late readiness"),
        }
        assert_eq!(
            polls.load(Ordering::SeqCst),
            before,
            "expired {operation} may not poll inner I/O"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn expired_idle_refuses_a_late_byte_before_consumption_or_clock_renewal() {
    let mut client = ReadinessIo::quiet();
    let mut target = ReadinessIo::quiet();
    let late_byte = client.read_mode.clone();
    let mut owner = Box::pin(forward(
        &mut client,
        &mut target,
        Duration::from_millis(100),
        Duration::from_secs(1),
    ));
    assert!(poll_once(owner.as_mut()).is_pending());
    tokio::time::advance(Duration::from_millis(101)).await;
    late_byte.store(1, Ordering::SeqCst);
    match poll_once(owner.as_mut()) {
        Poll::Ready(Err(error)) => assert_eq!(error.kind(), io::ErrorKind::TimedOut),
        _ => panic!("expired idle clock must refuse a late byte"),
    }
    assert_eq!(
        late_byte.load(Ordering::SeqCst),
        1,
        "expired owner must not consume late byte"
    );
}
