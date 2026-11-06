//! cfg(test)-only loopback latency link (B-06 S16h-1): a TCP proxy in front of
//! a loopback relay that holds every chunk for RTT/2 in each direction, so a
//! request and its answer pay one RTT as they would to a remote relay. Chunks
//! are pipelined (a later chunk waits only for its own delay), so the link adds
//! latency, not a bandwidth limit. The TCP handshake itself completes at
//! loopback speed, because the kernel answers it; every byte after it pays the
//! delay. A FIN is forwarded after the same delay. A link made
//! [`TestLink::with_uplink`] also reads the client's bytes at a fixed rate,
//! so a client upload queues in its own socket buffers as on a slow uplink.
//! Nothing here is reachable from a production build.
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpListener, TcpStream,
    },
    sync::{mpsc, oneshot},
    time::Instant,
};

/// The path RTT the S16h design budgets for (v19: about 170 ms).
pub(crate) const DEFAULT_RTT: Duration = Duration::from_millis(170);
/// The most a rate-limited direction reads at a time.
const RATE_CHUNK: usize = 2 * 1024;

/// A latency proxy on its own thread and runtime, in front of `upstream`.
pub(crate) struct TestLink {
    address: SocketAddr,
    rtt: Duration,
    connections: Arc<AtomicUsize>,
    clock_qos: u32,
    shutdown: Option<oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl TestLink {
    pub(crate) fn spawn(upstream: SocketAddr) -> Self {
        Self::with_rtt(upstream, DEFAULT_RTT)
    }

    pub(crate) fn with_rtt(upstream: SocketAddr, rtt: Duration) -> Self {
        Self::shaped(upstream, rtt, None)
    }

    /// `with_rtt` whose uplink (client to relay) carries `bytes_per_second`.
    pub(crate) fn with_uplink(upstream: SocketAddr, rtt: Duration, bytes_per_second: u32) -> Self {
        Self::shaped(upstream, rtt, Some(bytes_per_second))
    }

    fn shaped(upstream: SocketAddr, rtt: Duration, uplink: Option<u32>) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = connections.clone();
        let (shutdown, mut stop) = oneshot::channel::<()>();
        let one_way = rtt / 2;
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("aegis-ne-test-link".into())
            .spawn(move || {
                // This thread is the test's latency clock. A default-QoS
                // timer may coalesce past the link's existing 15 ms oracle.
                // Request/read back only this fixture thread's QoS; leave
                // the caller, product workers and process policy alone.
                let policy = fixture_thread_qos();
                let permitted = policy.is_ok();
                let _ = ready.send(policy);
                if !permitted {
                    return;
                }
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();
                runtime.block_on(async move {
                    let listener = TcpListener::from_std(listener).unwrap();
                    let mut links = Vec::new();
                    loop {
                        tokio::select! {
                            _ = &mut stop => break,
                            accepted = listener.accept() => {
                                let Ok((client, _)) = accepted else { continue };
                                counted.fetch_add(1, Ordering::SeqCst);
                                links.push(tokio::spawn(carry(client, upstream, one_way, uplink)));
                            }
                        }
                    }
                    for link in &links {
                        link.abort();
                    }
                });
            })
            .unwrap();
        let clock_qos = started
            .recv_timeout(Duration::from_secs(2))
            .expect("latency fixture thread did not start")
            .expect("latency fixture thread QoS refused");
        Self {
            address,
            rtt,
            connections,
            clock_qos,
            shutdown: Some(shutdown),
            thread: Some(thread),
        }
    }

    /// Where a client dials instead of the relay.
    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn rtt(&self) -> Duration {
        self.rtt
    }

    /// TCP connections the link accepted.
    pub(crate) fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

impl Drop for TestLink {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Apple sys/qos.h: QOS_CLASS_USER_INTERACTIVE is 0x21. Only owned fixture
/// threads request this policy. A clock-only request still leaves the echo
/// and sampling threads' I/O wakeups outside the unchanged 15 ms budget.
fn fixture_thread_qos() -> Result<u32, i32> {
    unsafe extern "C" {
        fn pthread_set_qos_class_self_np(class: u32, relative: i32) -> i32;
        fn qos_class_self() -> u32;
    }
    const REQUESTED: u32 = 0x21;
    let result = unsafe { pthread_set_qos_class_self_np(REQUESTED, 0) };
    if result != 0 {
        return Err(result);
    }
    let observed = unsafe { qos_class_self() };
    if observed != REQUESTED {
        return Err(libc::EINVAL);
    }
    Ok(observed)
}

/// One proxied connection: both directions delayed by `one_way`, the uplink
/// read at `uplink` bytes per second when set; it ends when both have
/// forwarded their FIN or failed.
async fn carry(client: TcpStream, upstream: SocketAddr, one_way: Duration, uplink: Option<u32>) {
    let Ok(server) = TcpStream::connect(upstream).await else {
        return;
    };
    // The link's own sockets must not add Nagle delay on top of its own.
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    let (client_read, client_write) = client.into_split();
    let (server_read, server_write) = server.into_split();
    tokio::join!(
        direction(client_read, server_write, one_way, uplink),
        direction(server_read, client_write, one_way, None)
    );
}

/// Copy `from` to `to`, each chunk written `one_way` after it was read. A FIN
/// is forwarded the same way, then this direction is done. With `rate`, at
/// most `RATE_CHUNK` bytes are read at a time and the next read waits as
/// long as `rate` takes to carry them.
async fn direction(from: OwnedReadHalf, to: OwnedWriteHalf, one_way: Duration, rate: Option<u32>) {
    // None is the FIN.
    let (queue, mut queued) = mpsc::unbounded_channel::<(Instant, Option<Vec<u8>>)>();
    let reader = async move {
        let mut from = from;
        let mut buffer = vec![
            0;
            if rate.is_some() {
                RATE_CHUNK
            } else {
                64 * 1024
            }
        ];
        loop {
            match from.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let _ = queue.send((Instant::now() + one_way, None));
                    // The writer ends this direction after the FIN.
                    std::future::pending::<()>().await;
                }
                Ok(read) => {
                    let due = Instant::now() + one_way;
                    if queue.send((due, Some(buffer[..read].to_vec()))).is_err() {
                        return;
                    }
                    if let Some(rate) = rate {
                        let carried = Duration::from_secs_f64(read as f64 / f64::from(rate));
                        tokio::time::sleep(carried).await;
                    }
                }
            }
        }
    };
    let writer = async move {
        let mut to = to;
        while let Some((due, chunk)) = queued.recv().await {
            tokio::time::sleep_until(due).await;
            match chunk {
                Some(chunk) => {
                    if to.write_all(&chunk).await.is_err() {
                        return;
                    }
                }
                None => {
                    // Half-close: the other direction may still carry data.
                    let _ = to.shutdown().await;
                    return;
                }
            }
        }
    };
    tokio::select! {
        _ = reader => {}
        _ = writer => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A loopback TCP echo server on its own thread for the link self-test.
    fn echo_server(delay: Duration) -> (SocketAddr, oneshot::Sender<()>, JoinHandle<()>, u32) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, mut stopped) = oneshot::channel::<()>();
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let thread = thread::spawn(move || {
            let policy = fixture_thread_qos();
            let permitted = policy.is_ok();
            let _ = ready.send(policy);
            if !permitted {
                return;
            }
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = TcpListener::from_std(listener).unwrap();
                loop {
                    tokio::select! {
                        _ = &mut stopped => break,
                        accepted = listener.accept() => {
                            let Ok((mut tcp, _)) = accepted else { continue };
                            let _ = tcp.set_nodelay(true);
                            tokio::spawn(async move {
                                let mut buffer = [0u8; 1024];
                                while let Ok(read) = tcp.read(&mut buffer).await {
                                    if read == 0 {
                                        break;
                                    }
                                    if !delay.is_zero() {
                                        tokio::time::sleep(delay).await;
                                    }
                                    if tcp.write_all(&buffer[..read]).await.is_err() {
                                        break;
                                    }
                                }
                            });
                        }
                    }
                }
            });
        });
        let qos = started
            .recv_timeout(Duration::from_secs(2))
            .expect("echo fixture thread did not start")
            .expect("echo fixture thread QoS refused");
        (address, stop, thread, qos)
    }

    #[test]
    fn test_link_echo_round_trip_is_the_configured_rtt() {
        // The libtest caller keeps its original policy. All three actors of
        // this clock self-test are separate owned threads, with QoS readback.
        thread::Builder::new()
            .name("aegis-ne-rtt-sample".into())
            .spawn(|| {
                let sampler_qos = fixture_thread_qos().expect("sampling fixture QoS refused");
                let (echo, stop, thread, echo_qos) = echo_server(Duration::ZERO);
                let link = TestLink::spawn(echo);
                assert_eq!(link.rtt(), Duration::from_millis(170));
                let samples = echo_samples(&link);
                assert_eq!(link.connections(), 1);
                let low = Duration::from_millis(155);
                let high = Duration::from_millis(185);
                // Preserve every original sample and both original bounds.
                assert!(samples.iter().all(|rtt| *rtt >= low), "{samples:?}");
                let mut sorted = samples.clone();
                sorted.sort();
                eprintln!(
                    "B06_TIMING link_clock_qos={} echo_qos={echo_qos} sampler_qos={sampler_qos} rtt_us={:?}",
                    link.clock_qos,
                    samples.iter().map(Duration::as_micros).collect::<Vec<_>>()
                );
                assert!(
                    sorted[2] <= high,
                    "median above 170 ms + 15 ms: {samples:?}"
                );
                drop(link);
                let _ = stop.send(());
                thread.join().unwrap();

                // A physical 40 ms echo delay must still exceed the same
                // oracle. QoS cannot turn real latency into an accepted RTT.
                let (echo, stop, thread, echo_qos) = echo_server(Duration::from_millis(40));
                let link = TestLink::spawn(echo);
                assert_eq!(link.rtt(), Duration::from_millis(170));
                let mut delayed = echo_samples(&link);
                assert_eq!(link.connections(), 1);
                assert!(delayed.iter().all(|rtt| *rtt >= low), "{delayed:?}");
                delayed.sort();
                eprintln!(
                    "B06_TIMING delayed_echo40_ms clock_qos={} echo_qos={echo_qos} sampler_qos={sampler_qos} rtt_us={:?}",
                    link.clock_qos,
                    delayed.iter().map(Duration::as_micros).collect::<Vec<_>>()
                );
                assert!(delayed[2] > high, "extra echo delay escaped the original RTT oracle: {delayed:?}");
                drop(link);
                let _ = stop.send(());
                thread.join().unwrap();
            })
            .unwrap()
            .join()
            .unwrap();
    }

    fn echo_samples(link: &TestLink) -> Vec<Duration> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut tcp = TcpStream::connect(link.address()).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            let mut samples = Vec::new();
            for round in 0..5u8 {
                let started = std::time::Instant::now();
                tcp.write_all(&[round]).await.unwrap();
                let mut echoed = [0u8; 1];
                tcp.read_exact(&mut echoed).await.unwrap();
                assert_eq!(echoed, [round]);
                samples.push(started.elapsed());
            }
            // A FIN reaches the far side after the delay and the echo server
            // then closes its side: the client reads EOF.
            tcp.shutdown().await.unwrap();
            let mut rest = Vec::new();
            tcp.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
            samples
        })
    }

    #[test]
    fn test_link_uplink_carries_its_rate() {
        const RATE: u32 = 32 * 1024;
        let (echo, stop, thread, _) = echo_server(Duration::ZERO);
        let link = TestLink::with_uplink(echo, Duration::from_millis(20), RATE);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let elapsed = runtime.block_on(async {
            let tcp = TcpStream::connect(link.address()).await.unwrap();
            tcp.set_nodelay(true).unwrap();
            let (mut read, mut write) = tcp.into_split();
            let sent = vec![7u8; 48 * 1024];
            let started = std::time::Instant::now();
            let writer = tokio::spawn(async move {
                write.write_all(&sent).await.unwrap();
                write
            });
            let mut echoed = vec![0u8; 48 * 1024];
            read.read_exact(&mut echoed).await.unwrap();
            assert!(echoed.iter().all(|byte| *byte == 7));
            drop(writer.await.unwrap());
            started.elapsed()
        });
        // 48 KiB at 32 KiB/s: one and a half seconds, the downlink unshaped.
        assert!(elapsed >= Duration::from_millis(1_400), "{elapsed:?}");
        assert!(elapsed <= Duration::from_millis(2_500), "{elapsed:?}");
        drop(link);
        let _ = stop.send(());
        thread.join().unwrap();
    }
}
