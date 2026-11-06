//! Explicit scoped native endurance test. Never changes physical DNS/default routes.
use super::*;
use std::sync::atomic::AtomicUsize;
use tokio::sync::watch;

struct Jobs(Vec<tokio::task::JoinHandle<()>>);
impl Drop for Jobs {
    fn drop(&mut self) {
        for job in &self.0 {
            job.abort();
        }
    }
}

async fn tcp_payload(
    target: SocketAddr,
    bytes: &[u8],
    downloaded: Option<&AtomicUsize>,
) -> io::Result<Vec<u8>> {
    let mut stream = tokio::net::TcpStream::connect(target).await?;
    stream.write_all(bytes).await?;
    stream.shutdown().await?;
    let mut received = Vec::new();
    let mut stream = stream.take(bytes.len() as u64 + 1);
    let mut buffer = [0; 16384];
    loop {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        received.extend_from_slice(&buffer[..n]);
        if let Some(downloaded) = downloaded {
            downloaded.fetch_add(n, Ordering::Relaxed);
        }
    }
    Ok(received)
}

// Same bounded progress contract as the native socket regression. OS-buffered
// writes are not progress: count the actual echo receiver and application reads.
async fn progressing<F: std::future::Future>(
    work: F,
    uploaded: &AtomicUsize,
    downloaded: &AtomicUsize,
    context: impl Fn() -> String,
) -> F::Output {
    tokio::pin!(work);
    let mut deadline = progress_deadline::ProgressDeadline::new(
        Instant::now(),
        Duration::from_secs(45),
        Duration::from_secs(180),
    );
    loop {
        tokio::select! {
            result = &mut work => return result,
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                let counters = (uploaded.load(Ordering::Relaxed), downloaded.load(Ordering::Relaxed), 0);
                assert!(!deadline.expired(Instant::now(), counters),
                    "{} stalled or exceeded total bound: uploaded={}, downloaded={}", context(), counters.0, counters.1);
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "administrator, AEGIS_TEST_WINTUN and AEGIS_SOAK_RESULT; scoped routes/process firewall, 30..3600 seconds"]
async fn native_tunnel_survives_relay_outages_and_repeated_flows() {
    let seconds: u64 = std::env::var("AEGIS_SOAK_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse()
        .unwrap();
    assert!((30..=3600).contains(&seconds));
    let result = std::path::PathBuf::from(std::env::var_os("AEGIS_SOAK_RESULT").unwrap());
    assert!(!result.exists(), "never overwrite earlier evidence");
    let _ = rustls::crypto::ring::default_provider().install_default();
    let inner_tls = match std::env::var("AEGIS_SOAK_INNER_TLS").as_deref() {
        Err(_) | Ok("0") => false,
        Ok("1") => true,
        _ => panic!("AEGIS_SOAK_INNER_TLS must be 0 or 1"),
    };
    let identity = tempfile::tempdir().unwrap();
    let (mut cfg, server) = if inner_tls {
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap().to_string();
        let (cfg, mut server_cfg) = crate::relay::secure_test_configs(identity.path(), &address);
        server_cfg
            .transport
            .inner_tls
            .as_mut()
            .unwrap()
            .idle_timeout_ms = 30000;
        drop(reservation);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            aegis_server::run_server_with_ready(server_cfg, Some(ready_tx))
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        (cfg, server)
    } else {
        crate::tests::start_local_masque_server().await
    };
    let mut jobs = Jobs(vec![server]);
    let original: SocketAddr = cfg.relay.server.parse().unwrap();
    let gate = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gate_addr = gate.local_addr().unwrap();
    let (availability, online) = watch::channel(true);
    jobs.0.push(tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = gate.accept() => {
                    let (mut client, _) = accepted.unwrap();
                    let mut online = online.clone();
                    if !*online.borrow_and_update() { continue; }
                    connections.spawn(async move {
                        // A generation change closes every existing carrier, even
                        // if a connection was still being established at outage time.
                        tokio::select! {
                            _ = online.changed() => {}
                            _ = async {
                                if let Ok(mut relay) = tokio::net::TcpStream::connect(original).await {
                                    let _ = tokio::io::copy_bidirectional(&mut client, &mut relay).await;
                                }
                            } => {}
                        }
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }));
    cfg.relay.server = gate_addr.to_string();
    cfg.relay.endpoints.clear();
    cfg.relay.transport_priority = vec![Family::GrpcStream];
    cfg.relay.udp_transport_priority = Some(vec![Family::GrpcDatagram]);
    let uploaded = Arc::new(AtomicUsize::new(0));
    let echo_uploaded = uploaded.clone();
    let downloaded = AtomicUsize::new(0);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = listener.local_addr().unwrap();
    jobs.0.push(tokio::spawn(async move {
        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let (mut stream, _) = accepted.unwrap();
                    let uploaded = echo_uploaded.clone();
                    connections.spawn(async move {
                        let mut bytes = Vec::new();
                        let result = tokio::time::timeout(Duration::from_secs(180), async {
                            let mut reader = (&mut stream).take(2 * 1024 * 1024 + 1);
                            let mut buffer = [0; 16384];
                            loop {
                                let n = reader.read(&mut buffer).await?;
                                if n == 0 { break; }
                                bytes.extend_from_slice(&buffer[..n]);
                                uploaded.fetch_add(n, Ordering::Relaxed);
                            }
                            stream.write_all(&bytes).await?;
                            stream.shutdown().await
                        }).await;
                        if !matches!(result, Ok(Ok(()))) {
                            eprintln!("soak echo failed after {} request bytes: {result:?}", bytes.len());
                        }
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }));
    let (udp, udp_job) = echo_udp("127.0.0.1".parse().unwrap()).await;
    jobs.0.push(udp_job);
    let driver = std::env::var_os("AEGIS_TEST_WINTUN").unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    // Only the first online round is captured; long endurance runs must not
    // overrun the existing 32MiB diagnostic bound or overwrite socket captures.
    let record_first_round = Arc::new(AtomicBool::new(true));
    let recording = record_first_round.clone();
    let mut guard = EngineStop {
        stop,
        thread: Some(std::thread::spawn(move || {
            let tun = Wintun::open(
                std::path::Path::new(&driver),
                &format!("AEGIS-Soak-{}", std::process::id()),
            )?;
            let mut net = NetworkGuard::configure(tun.luid, 1280, false)?;
            for route in ["198.18.0.0/16", "198.19.255.2/32", "fd00:ae61::2/128"] {
                net.capture(Prefix::parse(route).map_err(io::Error::other)?)?;
            }
            let _protection =
                ScopedProtection::install(tun.luid, &std::env::current_exe()?, &[gate_addr])?;
            let mut tun =
                RecordedPackets::with_recording(tun, "AEGIS_TEST_SOAK_PCAP", Some(recording))?;
            let _ = ready_tx.send(());
            run(
                &mut tun,
                cfg.relay,
                thread_stop,
                32,
                Duration::from_secs(5),
                1280,
                "9.9.9.9:53".parse().unwrap(),
            )
        })),
    };
    tokio::time::timeout(Duration::from_secs(15), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let started = Instant::now();
    let mut rounds = 0u64;
    let mut outages = 0u64;
    let mut max_recovery_ms = 0u128;
    let request = payload();
    let mut report_at = Instant::now();
    while started.elapsed() < Duration::from_secs(seconds) || outages == 0 {
        let stage = std::cell::Cell::new("IPv4 UDP DNS");
        let work = async {
            let dns = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            let question = dns_question("127.0.0.1");
            dns.send_to(&question, (ANCHOR_V4, 53)).await.unwrap();
            let mut answer = [0; 1500];
            let n = dns.recv(&mut answer).await.unwrap();
            assert!(n >= 16);
            assert_eq!(&answer[..2], &question[..2]);
            assert_eq!(answer[3] & 15, 0);
            let fake =
                std::net::Ipv4Addr::new(answer[n - 4], answer[n - 3], answer[n - 2], answer[n - 1]);
            assert_eq!(fake.octets()[..2], [198, 18]);
            stage.set("IPv6 TCP DNS");
            let mut dns6 = tokio::net::TcpStream::connect((ANCHOR_V6, 53))
                .await
                .unwrap();
            dns6.write_u16(question.len() as u16).await.unwrap();
            dns6.write_all(&question).await.unwrap();
            let size = dns6.read_u16().await.unwrap();
            let mut response = vec![0; size as usize];
            dns6.read_exact(&mut response).await.unwrap();
            assert!(response.ends_with(&fake.octets()));
            stage.set("TCP payload and half-close");
            let response = tcp_payload((fake, tcp.port()).into(), &request, Some(&downloaded))
                .await
                .unwrap();
            assert_eq!(response.len(), request.len());
            assert!(response == request, "TCP payload mismatch");
            // A slow TCP round may consume the DNS answer's 60-second TTL.
            // A new UDP flow needs a fresh mapping after the TCP lease ends.
            stage.set("refresh DNS before UDP");
            dns.send_to(&question, (ANCHOR_V4, 53)).await.unwrap();
            let n = dns.recv(&mut answer).await.unwrap();
            assert!(n >= 16);
            assert_eq!(&answer[..2], &question[..2]);
            assert_eq!(answer[3] & 15, 0);
            let fake =
                std::net::Ipv4Addr::new(answer[n - 4], answer[n - 3], answer[n - 2], answer[n - 1]);
            assert_eq!(fake.octets()[..2], [198, 18]);
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            for sequence in 0..4u8 {
                stage.set(if sequence == 0 {
                    "fragmented UDP"
                } else {
                    "small UDP"
                });
                let packet = vec![
                    sequence.wrapping_add(rounds as u8);
                    if sequence == 0 { 65000 } else { 1200 }
                ];
                socket.send_to(&packet, (fake, udp.port())).await.unwrap();
                let mut buffer = vec![0; 65535];
                let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                assert_eq!(peer, SocketAddr::from((fake, udp.port())));
                assert_eq!(size, packet.len());
                assert!(buffer[..size] == packet, "UDP payload mismatch");
            }
            fake
        };
        let fake = progressing(work, &uploaded, &downloaded, || {
            format!(
                "online data path at {}, round {rounds}, outages {outages}",
                stage.get()
            )
        })
        .await;
        record_first_round.store(false, Ordering::Release);
        rounds += 1;
        if rounds.is_multiple_of(5) {
            availability.send(false).unwrap();
            tokio::time::sleep(Duration::from_millis(200)).await;
            let blocked = tokio::time::timeout(
                Duration::from_secs(3),
                tcp_payload(
                    (fake, tcp.port()).into(),
                    b"outage-must-not-bypass-relay",
                    None,
                ),
            )
            .await;
            if let Ok(Ok(bytes)) = blocked {
                assert!(bytes.is_empty(), "payload escaped during relay outage");
            }
            availability.send(true).unwrap();
            let recovery = Instant::now();
            let response = progressing(
                tcp_payload((fake, tcp.port()).into(), &request, Some(&downloaded)),
                &uploaded,
                &downloaded,
                || format!("recovery round {rounds}, outages {outages}"),
            )
            .await
            .unwrap();
            assert_eq!(response.len(), request.len());
            assert!(response == request, "recovered TCP payload mismatch");
            max_recovery_ms = max_recovery_ms.max(recovery.elapsed().as_millis());
            outages += 1;
        }
        if report_at.elapsed() >= Duration::from_secs(30) {
            eprintln!(
                "scoped endurance: elapsed={}s rounds={rounds} outages={outages}",
                started.elapsed().as_secs()
            );
            report_at = Instant::now();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    guard.stop.store(true, Ordering::Release);
    let stats = guard.thread.take().unwrap().join().unwrap().unwrap();
    let evidence = serde_json::json!({"ok":true,"scope":"native_windows_scoped_local_relay","inner_tls":inner_tls,
        "elapsed_seconds":started.elapsed().as_secs(),"rounds":rounds,"outages":outages,
        "max_tcp_recovery_ms":max_recovery_ms,"idle_limit_seconds":45,"round_total_limit_seconds":180,"diagnostic_capture_scope":"first_online_round_only","tcp_payload_bytes":request.len(),
        "udp_payload_bytes":65000,"ipv4_udp_dns":true,"ipv6_tcp_dns":true,
        "early_boot_packet_capture_verified":false,"field_endurance_verified":false,"stats":stats});
    aegis_core::windows_file::write_private_new(
        &result,
        &serde_json::to_vec_pretty(&evidence).unwrap(),
        false,
    )
    .unwrap();
    eprintln!("{evidence}");
}
