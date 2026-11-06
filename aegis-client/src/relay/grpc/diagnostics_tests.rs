use super::*;
use std::time::Duration;
use tokio::sync::oneshot;

const WATCHDOG: Duration = Duration::from_secs(3);

#[tokio::test]
async fn withheld_actual_h2_driver_is_distinct_from_polled_driver() {
    tokio::time::timeout(WATCHDOG, async {
        let (local, remote) = tokio::io::duplex(16 * 1024);
        let witness = Witness::default();
        let (mut client, connection) = h2::client::handshake(witness.observe_io(local))
            .await
            .unwrap();
        let preface_bytes = witness.0.io.snapshot().write_bytes;
        assert!(
            preface_bytes > 0,
            "actual client preface reaches local I/O API"
        );
        let observed = witness.observe(connection);
        let (response, mut stream) = client.send_request(http::Request::new(()), false).unwrap();
        witness.request_queued();
        stream
            .send_data(bytes::Bytes::from_static(b"bounded fixture open"), false)
            .unwrap();
        witness.open_queued();
        let (release_tx, release_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            release_rx.await.unwrap();
            observed.await
        });
        let _guard = super::super::AbortOnDrop::new(task.abort_handle());
        let snapshot = witness.snapshot();
        assert!(snapshot.contains("h2_driver=spawned"));
        assert!(snapshot.contains("driver_polls=0"));
        assert!(snapshot.contains("request_queued=true, open_queued=true"));
        // The real server can consume the handshake written by client::handshake,
        // but request delivery requires polling the held client connection.
        let mut server = h2::server::handshake(remote).await.unwrap();
        let pending = std::future::poll_fn(|cx| {
            Poll::Ready(Pin::new(&mut server).poll_accept(cx).is_pending())
        })
        .await;
        assert!(
            pending,
            "queued request has not been delivered by a withheld driver"
        );
        release_tx.send(()).unwrap();
        let (request, _) = server.accept().await.unwrap().unwrap();
        assert!(witness.0.io.snapshot().write_bytes > preface_bytes);
        assert!(witness.snapshot().contains("tls_application_io=IoSnapshot"));
        assert!(witness.0.polls.load(Ordering::Relaxed) > 0);
        assert!(witness.0.pending.load(Ordering::Relaxed) > 0);
        drop(request);
        drop(response);
        drop(stream);
        drop(client);
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(witness.snapshot().contains("h2_driver=cancelled"));
    })
    .await
    .expect("held driver, actual request acceptance and owned cancellation are bounded");
}

#[tokio::test]
async fn actual_h2_driver_wake_and_invalid_settings_preserve_terminal_error() {
    use tokio::io::AsyncWriteExt;
    tokio::time::timeout(WATCHDOG, async {
        let (local, mut remote) = tokio::io::duplex(16 * 1024);
        let (_client, connection) = h2::client::handshake(local).await.unwrap();
        let witness = Witness::default();
        let mut observed = Box::pin(witness.observe(connection));
        let (pending_tx, pending_rx) = oneshot::channel();
        let mut pending_tx = Some(pending_tx);
        let task = tokio::spawn(async move {
            std::future::poll_fn(|cx| {
                let result = observed.as_mut().poll(cx);
                if result.is_pending() {
                    if let Some(tx) = pending_tx.take() {
                        tx.send(()).unwrap();
                    }
                }
                result
            })
            .await
        });
        let _guard = super::super::AbortOnDrop::new(task.abort_handle());
        pending_rx.await.unwrap();
        assert!(witness.snapshot().contains("h2_driver=polled"));
        // Actual malformed HTTP/2 frame: SETTINGS must use stream zero.
        // This is a wire fixture, not a manufactured h2::Error return value.
        remote
            .write_all(&[0, 0, 0, 4, 0, 0, 0, 0, 1])
            .await
            .unwrap();
        let error = task
            .await
            .unwrap()
            .expect_err("invalid peer SETTINGS is terminal");
        assert_eq!(error.reason(), Some(h2::Reason::PROTOCOL_ERROR));
        let snapshot = witness.snapshot();
        assert!(snapshot.contains("h2_driver=terminal_error"));
        assert!(snapshot.contains("driver_error=goaway"));
        assert!(witness.0.wakes.load(Ordering::Relaxed) > 0);
        assert!(witness.0.polls.load(Ordering::Relaxed) >= 2);
        assert!(!snapshot.contains("cancelled"));
    })
    .await
    .expect("actual pending poll, wake and terminal protocol error are bounded");
}

#[tokio::test]
async fn actual_h2_driver_peer_eof_without_stream_preserves_terminal_ok() {
    tokio::time::timeout(WATCHDOG, async {
        let (local, remote) = tokio::io::duplex(16 * 1024);
        let (_client, connection) = h2::client::handshake(local).await.unwrap();
        let witness = Witness::default();
        let mut observed = Box::pin(witness.observe(connection));
        let (pending_tx, pending_rx) = oneshot::channel();
        let mut pending_tx = Some(pending_tx);
        let driver = tokio::spawn(async move {
            std::future::poll_fn(|cx| {
                let result = observed.as_mut().poll(cx);
                if result.is_pending() {
                    if let Some(tx) = pending_tx.take() {
                        tx.send(()).unwrap();
                    }
                }
                result
            })
            .await
        });
        let _guard = super::super::AbortOnDrop::new(driver.abort_handle());
        // Establish the actual Pending boundary before EOF. EOF before this
        // flush can instead produce BrokenPipe; those are distinct phases.
        pending_rx.await.unwrap();
        drop(remote);
        // h2 legitimately reports Ok on EOF with no active streams. Record its
        // actual API result; terminal_ok is not a successful tunnel/open receipt.
        driver
            .await
            .unwrap()
            .expect("H2 EOF without active streams");
        let snapshot = witness.snapshot();
        assert!(snapshot.contains("h2_driver=terminal_ok"));
        assert!(snapshot.contains("driver_error=none"));
        assert!(witness.0.polls.load(Ordering::Relaxed) > 0);
        assert!(!snapshot.contains("cancelled"));
    })
    .await
    .expect("actual EOF driver is joined within the watchdog");
}

#[tokio::test]
async fn actual_h2_driver_peer_close_before_poll_preserves_io_error() {
    tokio::time::timeout(WATCHDOG, async {
        let (local, remote) = tokio::io::duplex(16 * 1024);
        let (_client, connection) = h2::client::handshake(local).await.unwrap();
        let witness = Witness::default();
        let observed = witness.observe(connection);
        assert!(witness.snapshot().contains("driver_polls=0"));
        drop(remote);
        let driver = tokio::spawn(observed);
        let _guard = super::super::AbortOnDrop::new(driver.abort_handle());
        let error = driver
            .await
            .unwrap()
            .expect_err("peer close before initial write must fail");
        assert!(error.is_io());
        let snapshot = witness.snapshot();
        assert!(snapshot.contains("h2_driver=terminal_error"));
        assert!(snapshot.contains("driver_error=io"));
        assert!(!snapshot.contains("cancelled"));
    })
    .await
    .expect("actual peer close before driver poll is bounded");
}
