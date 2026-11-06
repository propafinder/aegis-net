//! `AsyncRead`/`AsyncWrite` over one HTTP/2 stream.
//!
//! Exists for RFC 8441 (WebSocket over HTTP/2): once the extended CONNECT is
//! answered `200`, the stream carries WebSocket frames, and tungstenite wants
//! something that looks like a socket. This adapts the `h2` crate's
//! `SendStream`/`RecvStream` pair into that shape.
//!
//! The reason this matters for AEGIS is not tidiness. `https_ws` had to offer
//! ALPN `http/1.1` alone because the WebSocket Upgrade is an HTTP/1.1
//! mechanism, and that single choice made every relay ClientHello
//! distinguishable from Chrome — `h1` instead of `h2` in the JA4 head, and no
//! ALPS extension, since Chrome only sends ALPS alongside h2. With WebSocket
//! carried over h2, the client can offer Chrome's exact ALPN list.
//!
//! Receive window (v34). [`H2Stream::new`] re-opens exactly what each read
//! consumed, so a stream never holds more credit than SETTINGS_INITIAL_WINDOW_SIZE
//! and one stream's rate is bounded by that window per round trip.
//! [`H2Stream::with_recv_window`] adds a [`RecvWindowPolicy`], asked after every
//! release whether to grow or shrink this stream's window through the vendored
//! h2's `FlowControl::grow_window`/`shrink_window` (third_party/h2/AEGIS-PATCH.md).
//! The policy decides; this module only reports the window and applies steps.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

/// One stream's receive window as h2 holds it, read right after a release.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecvWindow {
    /// What the window re-opens to: SETTINGS_INITIAL_WINDOW_SIZE plus every
    /// accepted [`WindowStep::Grow`] minus every accepted
    /// [`WindowStep::Shrink`] (h2's available plus unreleased capacity).
    pub target: u32,
    /// Credit announced to the peer and not yet used by data received: an
    /// upper bound on what the peer may still send on this stream. It can
    /// exceed `target` after a shrink until the peer has sent the difference.
    pub peer: u32,
    /// Bytes h2 received on this stream and holds unreleased: buffered, not
    /// yet read (h2's used capacity). `peer + unreleased` is what this
    /// stream may hold in memory, received or still to come; it can exceed
    /// `target` after a shrink until the reader has caught up. Read after
    /// `peer`, so a DATA frame that lands between the two reads is counted
    /// twice, never missed.
    pub unreleased: u32,
}

/// A change a [`RecvWindowPolicy`] asks of its stream's receive window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowStep {
    /// Raise `target` by this many bytes of new credit on this stream only:
    /// one stream WINDOW_UPDATE (h2 batches it with the next update when it
    /// is under half the window the peer knows), no connection capacity.
    Grow(u32),
    /// Lower `target` by this many bytes. Nothing is sent and credit already
    /// announced is not revoked: `peer` falls to the new target only as the
    /// peer sends. Connection capacity is released as before.
    Shrink(u32),
}

/// Decides one [`H2Stream`]'s receive window; see [`H2Stream::with_recv_window`].
///
/// The policy is owned by its stream and dropped with it, after the stream's
/// h2 halves: dropping it is the notification that the stream is gone, so a
/// policy that holds shared budget returns it in its `Drop`. While the stream
/// lives, the policy is only called from the stream's reads, never on a timer:
/// a stream that receives nothing is not consulted.
pub trait RecvWindowPolicy {
    /// The stream just released `released` bytes (one received chunk) back
    /// to h2, which left the window at `window`; `now` is tokio's clock, so
    /// tests with paused time see virtual time. Returns the step to apply,
    /// if any.
    fn on_release(&mut self, released: u32, window: RecvWindow, now: Instant)
        -> Option<WindowStep>;

    /// h2 refused `step` and nothing changed: the stream no longer receives,
    /// a growth would pass 2^31-1, or a shrink exceeds `target`.
    fn refused(&mut self, step: WindowStep);
}

/// One HTTP/2 stream, presented as a byte stream.
pub struct H2Stream {
    send: h2::SendStream<Bytes>,
    recv: h2::RecvStream,
    /// Bytes received but not yet handed to the reader.
    pending: Bytes,
    /// Reserved-capacity state for the current write.
    write_reserved: usize,
    /// Optional response trailers sent on half-close instead of an empty
    /// END_STREAM DATA frame (`None` after they have been sent).
    end_trailers: Option<http::HeaderMap>,
    trailers_configured: bool,
    /// The receive-window policy, if any. Declared last so it drops after
    /// `send` and `recv`.
    recv_window: Option<Box<dyn RecvWindowPolicy + Send>>,
}

impl H2Stream {
    pub fn new(send: h2::SendStream<Bytes>, recv: h2::RecvStream) -> Self {
        Self {
            send,
            recv,
            pending: Bytes::new(),
            write_reserved: 0,
            end_trailers: None,
            trailers_configured: false,
            recv_window: None,
        }
    }

    /// Finish this (server) stream with a well-formed gRPC trailer block
    /// (`grpc-status: 0`) rather than a bare END_STREAM. CDN gRPC proxies
    /// expect gRPC responses to end with trailers; the half-close meaning is
    /// unchanged because the peer's reader sees end of stream either way.
    pub fn with_grpc_ok_trailers(mut self) -> Self {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        self.end_trailers = Some(trailers);
        self.trailers_configured = true;
        self
    }

    /// [`H2Stream::new`], with `policy` asked after every receive release
    /// whether to grow or shrink this stream's window. Writes, errors and
    /// every byte read are as with `new`; only window credit differs.
    pub fn with_recv_window(
        send: h2::SendStream<Bytes>,
        recv: h2::RecvStream,
        policy: Box<dyn RecvWindowPolicy + Send>,
    ) -> Self {
        Self {
            recv_window: Some(policy),
            ..Self::new(send, recv)
        }
    }
}

fn recv_window(flow: &h2::FlowControl) -> RecvWindow {
    let target = flow.available_capacity() as i64 + flow.used_capacity() as i64;
    // Each read takes h2's lock on its own, and the connection task may take
    // a DATA frame between them: it lowers the peer's credit and raises the
    // unreleased bytes by the same amount. The credit first, so the sum can
    // only come out too high.
    let peer = u32::try_from(flow.peer_window_size()).unwrap_or(u32::MAX);
    let unreleased = u32::try_from(flow.used_capacity()).unwrap_or(u32::MAX);
    RecvWindow {
        target: target.clamp(0, i64::from(u32::MAX)) as u32,
        peer,
        unreleased,
    }
}

/// Asks `policy` about a release of `released` bytes and applies its step.
/// A refusal is reported to the policy and does not fail the read.
fn step_recv_window(
    policy: &mut (dyn RecvWindowPolicy + Send),
    flow: &mut h2::FlowControl,
    released: usize,
) {
    let released = u32::try_from(released).unwrap_or(u32::MAX);
    let Some(step) = policy.on_release(released, recv_window(flow), Instant::now()) else {
        return;
    };
    let applied = match step {
        WindowStep::Grow(bytes) => flow.grow_window(bytes as usize),
        WindowStep::Shrink(bytes) => flow.shrink_window(bytes as usize),
    };
    if applied.is_err() {
        policy.refused(step);
    }
}

fn h2_io_error(err: h2::Error) -> io::Error {
    if err.is_io() {
        // Prefer the underlying io error so callers' benign-close checks
        // (ConnectionReset, BrokenPipe, ...) keep working unchanged.
        if let Some(io_err) = err.into_io() {
            return io_err;
        }
        return io::Error::new(io::ErrorKind::BrokenPipe, "h2 io error");
    }
    match err.reason() {
        Some(h2::Reason::NO_ERROR) | Some(h2::Reason::CANCEL) | Some(h2::Reason::STREAM_CLOSED) => {
            io::Error::new(io::ErrorKind::ConnectionReset, err)
        }
        _ => io::Error::other(err),
    }
}

impl AsyncRead for H2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.pending.is_empty() {
                let take = this.pending.len().min(buf.remaining());
                buf.put_slice(&this.pending[..take]);
                this.pending.advance(take);
                return Poll::Ready(Ok(()));
            }
            match ready!(this.recv.poll_data(cx)) {
                // EOF: the peer half-closed the stream.
                None => return Poll::Ready(Ok(())),
                Some(Err(err)) => return Poll::Ready(Err(h2_io_error(err))),
                Some(Ok(chunk)) => {
                    // Give the window straight back. h2 hands out a fixed
                    // receive window and only re-opens it when the application
                    // releases what it consumed; forgetting this is what
                    // stalled the gRPC transport at ~64 KiB.
                    let len = chunk.len();
                    if len > 0 {
                        this.recv
                            .flow_control()
                            .release_capacity(len)
                            .map_err(h2_io_error)?;
                        if let Some(policy) = this.recv_window.as_mut() {
                            step_recv_window(policy.as_mut(), this.recv.flow_control(), len);
                        }
                    }
                    this.pending = chunk;
                }
            }
        }
    }
}

impl AsyncWrite for H2Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Reserve once and KEEP the reservation across polls.
        //
        // The bookkeeping used to be cleared before the `take == 0` check
        // below, so a poll that was granted nothing dropped the intent and the
        // next poll re-reserved — with a possibly different buffer length,
        // since the caller is free to hand us a different slice each time.
        // Re-request only when the caller now wants more than we asked for.
        if this.write_reserved < buf.len() {
            this.send.reserve_capacity(buf.len());
            this.write_reserved = buf.len();
        }
        // poll_capacity reports an increase, not the current balance. After
        // a smaller write consumes only part of an earlier reservation, h2
        // can already have capacity without another increase to wake us.
        let available = this.send.capacity();
        let granted = if available > 0 {
            available
        } else {
            match ready!(this.send.poll_capacity(cx)) {
                None => {
                    this.write_reserved = 0;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "h2 stream closed while writing",
                    )));
                }
                Some(Err(err)) => {
                    this.write_reserved = 0;
                    return Poll::Ready(Err(h2_io_error(err)));
                }
                Some(Ok(granted)) => granted,
            }
        };
        let take = granted.min(buf.len());
        if take == 0 {
            // No capacity yet; poll_capacity registered the waker. The
            // reservation stands — clearing it here is what caused the
            // re-reserve loop.
            return Poll::Pending;
        }
        // Data is going out now, so the reservation is consumed.
        this.write_reserved = this.write_reserved.saturating_sub(take);
        this.send
            .send_data(Bytes::copy_from_slice(&buf[..take]), false)
            .map_err(h2_io_error)?;
        Poll::Ready(Ok(take))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // h2 owns its own send buffering and flushes on the connection task.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.trailers_configured {
            // Trailers carry END_STREAM. A repeated shutdown is a no-op, as
            // the stream's send half is already closed.
            if let Some(trailers) = this.end_trailers.take() {
                this.send.send_trailers(trailers).map_err(h2_io_error)?;
            }
            return Poll::Ready(Ok(()));
        }
        // Half-close: END_STREAM with no payload, matching a TCP FIN.
        this.send
            .send_data(Bytes::new(), true)
            .map_err(h2_io_error)?;
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn grpc_ok_trailers_end_the_stream_as_a_half_close() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let worker = tokio::spawn(async move {
                let mut stream = H2Stream::new(send, request.into_body()).with_grpc_ok_trailers();
                let mut bytes = vec![];
                stream.read_to_end(&mut bytes).await.unwrap();
                stream.write_all(&bytes).await.unwrap();
                stream.shutdown().await.unwrap();
                // Idempotent after the trailer block closed the send half.
                stream.shutdown().await.unwrap();
            });
            tokio::select! {
                result = worker => result.unwrap(),
                _ = connection.accept() => panic!("unexpected connection termination"),
            }
            // Keep driving until the client has read the trailers.
            let _ =
                tokio::time::timeout(std::time::Duration::from_secs(1), connection.accept()).await;
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let (response, mut send) = client.send_request(http::Request::new(()), false).unwrap();
        send.send_data(Bytes::from_static(b"echo"), true).unwrap();
        let mut body = response.await.unwrap().into_body();
        let mut echoed = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            body.flow_control().release_capacity(chunk.len()).unwrap();
            echoed.extend_from_slice(&chunk);
        }
        let trailers = body.trailers().await.unwrap().expect("gRPC trailers");
        assert_eq!(echoed, b"echo");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");
        server.await.unwrap();
        driver.abort();
    }

    #[tokio::test]
    async fn smaller_write_consumes_capacity_left_by_previous_reservation() {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let reader = tokio::spawn(async move {
                let mut stream = H2Stream::new(send, request.into_body());
                let mut bytes = vec![];
                stream.read_to_end(&mut bytes).await.unwrap();
                bytes
            });
            tokio::select! {
                result = reader => result.unwrap(),
                _ = connection.accept() => panic!("unexpected connection termination"),
            }
        });
        let (mut client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let (response, send) = client.send_request(http::Request::new(()), false).unwrap();
        let mut stream = H2Stream::new(send, response.await.unwrap().into_body());
        // A pending write may be cancelled and retried with a smaller slice.
        // Keep its larger reservation, exactly as poll_write does.
        stream.send.reserve_capacity(64);
        stream.write_reserved = 64;
        let transfer = async {
            stream.write_all(&[1; 8]).await.unwrap();
            stream.write_all(&[2; 16]).await.unwrap();
            stream.shutdown().await.unwrap();
            server.await.unwrap()
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), transfer).await;
        driver.abort();
        assert_eq!(
            result.expect("unused assigned capacity must not stall"),
            [&[1; 8][..], &[2; 16][..]].concat()
        );
    }
}

/// The receive side on the wire, for `H2Stream::new` and with a policy (v34):
/// a real h2 server sends one body through `H2Stream::new`, a real h2 client
/// reads it, and every frame between them is recorded as it crosses. The
/// client receives, as the macOS pool does, with that pool's v33 windows.
#[cfg(test)]
mod recv_window_tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};

    /// The pool's SETTINGS_INITIAL_WINDOW_SIZE and connection window at v33.
    const WINDOW: u32 = 131_072;
    const CONN_WINDOW: u32 = 8 * 1024 * 1024;
    const DATA: u8 = 0x0;
    const WINDOW_UPDATE: u8 = 0x8;
    /// Body bytes: several stream windows and an odd tail.
    const TOTAL: usize = 1_048_576 + 12_345;

    /// One frame as it crossed: who sent it, its type, its stream and its
    /// DATA length or WINDOW_UPDATE increment (0 for other types).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Frame {
        from_client: bool,
        kind: u8,
        stream: u32,
        value: u32,
    }

    type Frames = Arc<Mutex<Vec<Frame>>>;

    async fn record(
        mut from: ReadHalf<DuplexStream>,
        mut to: WriteHalf<DuplexStream>,
        frames: Frames,
        from_client: bool,
    ) {
        if from_client {
            let mut preface = [0; 24];
            if from.read_exact(&mut preface).await.is_err() || to.write_all(&preface).await.is_err()
            {
                return;
            }
        }
        loop {
            let mut head = [0; 9];
            if from.read_exact(&mut head).await.is_err() {
                return;
            }
            let len = u32::from_be_bytes([0, head[0], head[1], head[2]]);
            let mut payload = vec![0; len as usize];
            if from.read_exact(&mut payload).await.is_err() {
                return;
            }
            let value = match head[3] {
                DATA => len,
                WINDOW_UPDATE => {
                    u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]])
                        & 0x7fff_ffff
                }
                _ => 0,
            };
            frames.lock().unwrap().push(Frame {
                from_client,
                kind: head[3],
                stream: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
                value,
            });
            if to.write_all(&head).await.is_err() || to.write_all(&payload).await.is_err() {
                return;
            }
        }
    }

    fn body() -> Vec<u8> {
        (0..TOTAL).map(|i| (i % 251) as u8).collect()
    }

    /// How the client reads the body.
    #[derive(Clone, Copy, Debug)]
    enum Reader {
        /// `read_to_end`: drains whatever h2 buffered at once.
        ToEnd,
        /// One DATA frame's worth per read, letting every task run between.
        Yielding,
        /// One DATA frame's worth per read, then a sleep on tokio's clock.
        Sleeping(Duration),
    }

    /// One response body of `TOTAL` bytes, read to its end through `open`'s
    /// stream. Returns every frame that crossed, in order.
    async fn transfer<F>(open: F, reader: Reader) -> Vec<Frame>
    where
        F: FnOnce(h2::SendStream<Bytes>, h2::RecvStream) -> H2Stream,
    {
        let (client_io, tap_client) = tokio::io::duplex(1 << 20);
        let (tap_server, server_io) = tokio::io::duplex(1 << 20);
        let frames = Frames::default();
        let (from_client, to_client) = tokio::io::split(tap_client);
        let (from_server, to_server) = tokio::io::split(tap_server);
        tokio::spawn(record(from_client, to_server, frames.clone(), true));
        tokio::spawn(record(from_server, to_client, frames.clone(), false));
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            let (request, mut respond) = connection.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let _writer = tokio::spawn(async move {
                let mut stream = H2Stream::new(send, request.into_body());
                stream.write_all(&body()).await.unwrap();
                stream.shutdown().await.unwrap();
                // Held open until the connection ends, as a relay's would be.
                std::future::pending::<()>().await;
            });
            // Drive the connection until the client goes, so every buffered
            // DATA frame is written.
            while let Some(Ok(_)) = connection.accept().await {}
        });
        let (mut client, connection) = h2::client::Builder::new()
            .initial_window_size(WINDOW)
            .initial_connection_window_size(CONN_WINDOW)
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        let (response, send) = client.send_request(http::Request::new(()), false).unwrap();
        let mut stream = open(send, response.await.unwrap().into_body());
        let mut read = Vec::new();
        let reading = async {
            let pause = match reader {
                Reader::ToEnd => return stream.read_to_end(&mut read).await.map(drop),
                Reader::Yielding => None,
                Reader::Sleeping(pause) => Some(pause),
            };
            let mut chunk = vec![0; 16_384];
            loop {
                let n = stream.read(&mut chunk).await?;
                if n == 0 {
                    return Ok(());
                }
                read.extend_from_slice(&chunk[..n]);
                match pause {
                    Some(pause) => tokio::time::sleep(pause).await,
                    None => {
                        for _ in 0..8 {
                            tokio::task::yield_now().await;
                        }
                    }
                }
            }
        };
        tokio::time::timeout(Duration::from_secs(10), reading)
            .await
            .expect("the transfer must not stall")
            .unwrap();
        assert!(read == body(), "the body arrived intact");
        // Let the client's connection task send what the last read released.
        for _ in 0..64 {
            tokio::task::yield_now().await;
        }
        drop(stream);
        let frames = frames.lock().unwrap().clone();
        driver.abort();
        server.abort();
        frames
    }

    /// (stream, increment) of every WINDOW_UPDATE the client sent.
    fn updates(frames: &[Frame]) -> Vec<(u32, u32)> {
        frames
            .iter()
            .filter(|frame| frame.from_client && frame.kind == WINDOW_UPDATE)
            .map(|frame| (frame.stream, frame.value))
            .collect()
    }

    /// The server's stream credit after each frame crossed: the SETTINGS
    /// window plus the client's stream updates minus the server's DATA.
    fn peer_credit(frames: &[Frame]) -> Vec<i64> {
        let mut credit = i64::from(WINDOW);
        let mut series = Vec::with_capacity(frames.len());
        for frame in frames.iter().filter(|frame| frame.stream == 1) {
            match (frame.from_client, frame.kind) {
                (true, WINDOW_UPDATE) => credit += i64::from(frame.value),
                (false, DATA) => credit -= i64::from(frame.value),
                _ => {}
            }
            series.push(credit);
        }
        series
    }

    /// What b9adfe19 (v33) sent for each reader, captured from its
    /// `H2Stream::new` before the policy existed: the connection update of
    /// the pool's 8 MiB window (8_323_073), then the stream updates.
    fn v33_updates(reader: Reader) -> Vec<(u32, u32)> {
        let (increment, count) = match reader {
            Reader::ToEnd => (131_072, 8),
            Reader::Yielding => (16_384, 57),
            Reader::Sleeping(_) => unreachable!("not captured"),
        };
        std::iter::once((0, CONN_WINDOW - 65_535))
            .chain(std::iter::repeat_n((1, increment), count))
            .collect()
    }

    /// Everything a [`Probe`] was told, shared with the test.
    #[derive(Default)]
    struct Log {
        /// (released, window, now) of every `on_release`.
        calls: Vec<(u32, RecvWindow, Instant)>,
        steps: Vec<WindowStep>,
        refused: Vec<WindowStep>,
        dropped: bool,
    }

    type Shared = Arc<Mutex<Log>>;

    /// A policy that answers with `script` and records every call.
    struct Probe<F> {
        log: Shared,
        script: F,
    }

    impl<F> RecvWindowPolicy for Probe<F>
    where
        F: FnMut(u32, RecvWindow) -> Option<WindowStep>,
    {
        fn on_release(
            &mut self,
            released: u32,
            window: RecvWindow,
            now: Instant,
        ) -> Option<WindowStep> {
            let step = (self.script)(released, window);
            let mut log = self.log.lock().unwrap();
            log.calls.push((released, window, now));
            log.steps.extend(step);
            step
        }

        fn refused(&mut self, step: WindowStep) {
            self.log.lock().unwrap().refused.push(step);
        }
    }

    impl<F> Drop for Probe<F> {
        fn drop(&mut self) {
            self.log.lock().unwrap().dropped = true;
        }
    }

    fn probe<F>(
        script: F,
    ) -> (
        Shared,
        impl FnOnce(h2::SendStream<Bytes>, h2::RecvStream) -> H2Stream,
    )
    where
        F: FnMut(u32, RecvWindow) -> Option<WindowStep> + Send + 'static,
    {
        let log = Shared::default();
        let policy = Probe {
            log: log.clone(),
            script,
        };
        let open = move |send, recv| H2Stream::with_recv_window(send, recv, Box::new(policy));
        (log, open)
    }

    #[tokio::test]
    async fn new_sends_the_window_updates_v33_sent() {
        for reader in [Reader::ToEnd, Reader::Yielding] {
            for _ in 0..3 {
                let frames = transfer(H2Stream::new, reader).await;
                assert_eq!(updates(&frames), v33_updates(reader), "{reader:?}");
                // v33's bound: the peer never holds more than the SETTINGS window.
                assert!(peer_credit(&frames)
                    .iter()
                    .all(|&credit| credit <= i64::from(WINDOW)));
            }
        }
    }

    #[tokio::test]
    async fn a_policy_that_never_steps_sends_what_new_sends() {
        for reader in [Reader::ToEnd, Reader::Yielding] {
            let (log, open) = probe(|_, _| None);
            assert_eq!(updates(&transfer(open, reader).await), v33_updates(reader));
            let log = log.lock().unwrap();
            // Asked after every released chunk, every byte counted once.
            let released: usize = log.calls.iter().map(|call| call.0 as usize).sum();
            assert_eq!(released, TOTAL);
            assert!(log
                .calls
                .iter()
                .all(|call| call.1.target == WINDOW && call.1.peer <= WINDOW));
            // What the stream holds, buffered or still to come, never
            // exceeds its window (one runtime thread: no frame lands
            // between the reads).
            assert!(log
                .calls
                .iter()
                .all(|call| call.1.peer + call.1.unreleased <= WINDOW));
            assert!(log.steps.is_empty() && log.refused.is_empty());
            assert!(log.dropped, "dropped with its stream");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_window_counts_what_h2_holds_unreleased() {
        // A reader that sleeps after each frame lets h2 buffer what the
        // server already sent: those bytes are unreleased, most of the
        // window at a time, and with the credit still to come they stay
        // within the window the stream re-opens to.
        let (log, open) = probe(|_, _| None);
        transfer(open, Reader::Sleeping(Duration::from_millis(90))).await;
        {
            let log = log.lock().unwrap();
            let most = log.calls.iter().map(|call| call.1.unreleased).max();
            assert!(most.unwrap() > WINDOW / 2, "{most:?}");
            assert!(log
                .calls
                .iter()
                .all(|call| call.1.peer + call.1.unreleased <= call.1.target));
        }
        // At the last release of a reader that drains at once, nothing is
        // left unreleased.
        let (log, open) = probe(|_, _| None);
        transfer(open, Reader::ToEnd).await;
        let last = log.lock().unwrap().calls.last().unwrap().1;
        assert_eq!(last.unreleased, 0, "{last:?}");
    }

    #[tokio::test]
    async fn a_growth_is_stream_credit_the_peer_uses_with_the_connection_window_unchanged() {
        for reader in [Reader::ToEnd, Reader::Yielding] {
            let mut first = true;
            let (log, open) =
                probe(move |_, _| std::mem::take(&mut first).then_some(WindowStep::Grow(WINDOW)));
            let frames = transfer(open, reader).await;
            let connection = |updates: Vec<(u32, u32)>| {
                updates
                    .into_iter()
                    .filter(|update| update.0 == 0)
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                connection(updates(&frames)),
                connection(v33_updates(reader))
            );
            // The peer held more than the SETTINGS window, at most the grown one.
            let peak = peer_credit(&frames).into_iter().max().unwrap();
            assert!(peak > i64::from(WINDOW), "{reader:?} {peak}");
            assert!(peak <= 2 * i64::from(WINDOW), "{reader:?} {peak}");
            let log = log.lock().unwrap();
            assert_eq!(log.steps, [WindowStep::Grow(WINDOW)]);
            assert!(log.refused.is_empty());
            assert_eq!(log.calls[0].1.target, WINDOW);
            assert!(log.calls[1..]
                .iter()
                .all(|call| call.1.target == 2 * WINDOW));
            assert!(log.dropped);
        }
    }

    #[tokio::test]
    async fn a_refused_step_is_reported_and_changes_nothing() {
        for reader in [Reader::ToEnd, Reader::Yielding] {
            let mut script = vec![WindowStep::Shrink(u32::MAX), WindowStep::Grow(u32::MAX)];
            let (log, open) = probe(move |_, _| script.pop());
            assert_eq!(updates(&transfer(open, reader).await), v33_updates(reader));
            let log = log.lock().unwrap();
            let both = [WindowStep::Grow(u32::MAX), WindowStep::Shrink(u32::MAX)];
            assert_eq!(log.steps, both);
            assert_eq!(log.refused, both);
            assert!(log.calls.iter().all(|call| call.1.target == WINDOW));
        }
    }

    #[tokio::test]
    async fn a_shrink_lets_the_peer_credit_fall_to_the_lowered_target() {
        for reader in [Reader::ToEnd, Reader::Yielding] {
            let (mut read, mut grown, mut shrunk) = (0u64, false, false);
            let (log, open) = probe(move |released, _| {
                read += u64::from(released);
                if !std::mem::replace(&mut grown, true) {
                    Some(WindowStep::Grow(WINDOW))
                } else if read >= 4 * u64::from(WINDOW) && !std::mem::replace(&mut shrunk, true) {
                    Some(WindowStep::Shrink(WINDOW))
                } else {
                    None
                }
            });
            let frames = transfer(open, reader).await;
            let log = log.lock().unwrap();
            assert_eq!(
                log.steps,
                [WindowStep::Grow(WINDOW), WindowStep::Shrink(WINDOW)]
            );
            assert!(log.refused.is_empty());
            let shrunk_at = log.calls[1..]
                .iter()
                .position(|call| call.1.target == WINDOW)
                .map(|index| index + 1)
                .expect("the target came back down");
            // From the shrink on, the target stays down and the peer's credit
            // never rises above what it held; it ends at or below the target.
            let after = &log.calls[shrunk_at..];
            assert!(after.iter().all(|call| call.1.target == WINDOW));
            assert!(after
                .windows(2)
                .all(|pair| pair[1].1.peer <= pair[0].1.peer.max(WINDOW)));
            assert!(after.last().unwrap().1.peer <= WINDOW, "{reader:?}");
            // At the last release nothing is left unread.
            assert_eq!(after.last().unwrap().1.unreleased, 0, "{reader:?}");
            assert!(
                *peer_credit(&frames).last().unwrap() <= i64::from(WINDOW),
                "{reader:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn the_policy_is_given_tokio_time() {
        let pause = Duration::from_millis(90);
        let (log, open) = probe(|_, _| None);
        transfer(open, Reader::Sleeping(pause)).await;
        let log = log.lock().unwrap();
        assert!(log.calls.len() > 8);
        // Paused virtual time: each read follows a 90 ms sleep.
        assert!(log
            .calls
            .windows(2)
            .all(|pair| pair[1].2 - pair[0].2 >= pause));
    }
}
