use super::*;
use crate::secure_channel::*;
use sha2::{Digest, Sha256};

async fn startup_guard_owner(end: Instant) -> (OwnedSender, timing::Observer, UdpSocket) {
    let source = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let application = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    source
        .connect(application.local_addr().unwrap())
        .await
        .unwrap();
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    sink.connect(peer.local_addr().unwrap()).await.unwrap();
    peer.connect(sink.local_addr().unwrap()).await.unwrap();
    let mut sender = Sender::new(source, sink).unwrap();
    let observer = timing::Observer::default();
    sender.observe(observer.clone());
    let prepared = Prepared::new(settings(), Zeroizing::new([5; 32]), end).unwrap();
    let words = prepared.encode(b"x").unwrap();
    let start = Instant::now() + Duration::from_millis(200);
    let owner = OwnedSender::spawn_timing_cancelled_at_start(sender, &prepared, &words, start, end)
        .unwrap();
    (owner, observer, peer)
}

#[tokio::test]
async fn sdk_ready_failure_preserves_actual_prepare_error_and_observes_same_actor_join() {
    let end = Instant::now() + Duration::from_secs(10);
    let (owner, observer, peer) = startup_guard_owner(end).await;
    let callbacks = std::sync::atomic::AtomicUsize::new(0);
    let error = ready_owner(owner, end, || {
        callbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::Interrupted);
    assert_eq!(
        error
            .get_ref()
            .unwrap()
            .downcast_ref::<timing::Phase>()
            .unwrap()
            .0,
        "owned_release_cancelled"
    );
    assert_eq!(callbacks.load(std::sync::atomic::Ordering::SeqCst), 0);
    let observed = observer.snapshot();
    assert!(observed.release_thread_started);
    assert!(observed.release_thread_terminal);
    assert!(observed.release_thread_joined);
    assert_eq!(observed.accepted_packets, 0);
    assert_eq!(observed.sent_packets, 0);
    assert_eq!(observed.native_recv_attempts, 0);
    assert_eq!(observed.native_send_attempts, 0);
    assert_eq!(
        peer.try_recv(&mut [0; 32]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

#[tokio::test(start_paused = true)]
async fn sdk_ready_failure_expired_end_never_renews_or_invents_join() {
    let original_end = Instant::now() + Duration::from_secs(10);
    let (owner, observer, peer) = startup_guard_owner(original_end).await;
    tokio::time::advance(Duration::from_secs(10)).await;
    let callbacks = std::sync::atomic::AtomicUsize::new(0);
    let error = ready_owner(owner, original_end, || {
        callbacks.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    })
    .await
    .err()
    .unwrap();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(callbacks.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(!observer.snapshot().release_thread_joined);
    assert_eq!(observer.snapshot().sent_packets, 0);
    assert_eq!(
        peer.try_recv(&mut [0; 32]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
}

use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};

struct Fixture {
    _dir: tempfile::TempDir,
    client: ClientSettings,
    server: ServerSettings,
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(vec![]).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_path = dir.path().join("ca.pem");
    std::fs::write(&ca_path, ca.pem()).unwrap();
    let mut identities = Vec::new();
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("device.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        let cert_path = dir.path().join(format!("{name}.pem"));
        let key_path = dir.path().join(format!("{name}.key"));
        std::fs::write(&cert_path, cert.pem()).unwrap();
        #[cfg(windows)]
        crate::windows_file::write_private_new(&key_path, key.serialize_pem().as_bytes(), false)
            .unwrap();
        #[cfg(not(windows))]
        std::fs::write(&key_path, key.serialize_pem()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        identities.push((
            cert_path,
            key_path,
            hex::encode(Sha256::digest(cert.der().as_ref())),
        ));
    }
    Fixture {
        client: ClientSettings {
            server_name: "inner.test".into(),
            server_ca: ca_path.clone(),
            cert: identities[1].0.clone(),
            key: identities[1].1.clone(),
        },
        server: ServerSettings {
            device_registry: None,
            cert: identities[0].0.clone(),
            key: identities[0].1.clone(),
            client_ca: ca_path,
            allowed_client_sha256: vec![identities[1].2.clone()],
            admission: Default::default(),
            handshake_timeout_ms: 1000,
            idle_timeout_ms: 1000,
        },
        _dir: dir,
    }
}

fn settings() -> Settings {
    Settings {
        lambda_pps: 200,
        delta_pps: 20,
        reference_epsilon_milli: 500,
        service_mu_pps: 2000,
        buffering_ms: 200,
        block_ms: 100,
        bits_per_block: 6,
        payload_capacity: 1,
        max_word_events: 128,
        fifo_packets: 2048,
        total_packets: 8192,
        packet_bytes: 128,
        ready_lead_ms: 200,
        clock_uncertainty_us: 10_000,
        release_lateness_us: 10_000,
        drain_ms: 200,
        finalize_ms: 1000,
        precision_poll_budget: 2_000_000,
    }
}
async fn profile() -> Profile {
    let mut sockets = Vec::new();
    for _ in 0..6 {
        sockets.push(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    }
    let addresses: Vec<_> = sockets.iter().map(|s| s.local_addr().unwrap()).collect();
    Profile {
        resource_sha256: [1; 32],
        sender_application_bind: addresses[0],
        sender_application_peer: addresses[1],
        sender_packet_bind: addresses[2],
        receiver_packet_bind: addresses[3],
        receiver_application_bind: addresses[4],
        receiver_application_peer: addresses[5],
        timing: settings(),
    }
}
#[tokio::test]
async fn fixed_public_metadata_does_not_carry_record_or_word_and_rejects_count() {
    let p = profile().await;
    let mut cs: Vec<_> = (0..p.timing.blocks() + 2)
        .map(|slot| Checkpoint {
            ordinal: slot as u16,
            hashes: vec![],
        })
        .collect();
    let a = metadata(&p, &cs).unwrap();
    cs[1].hashes.push([5; 32]);
    let b = metadata(&p, &cs).unwrap();
    assert_eq!(a.len(), b.len());
    assert_eq!(a.len(), p.metadata_size().unwrap());
    assert_eq!(parse_metadata(&p, &b).unwrap()[1].hashes.len(), 1);
    let mut wrong = b.to_vec();
    wrong[10..12].copy_from_slice(&u16::MAX.to_be_bytes());
    assert!(parse_metadata(&p, &wrong).is_err());
    let value = serde_json::to_value(&p).unwrap();
    let mut unknown = value;
    unknown
        .as_object_mut()
        .unwrap()
        .insert("legitimate".into(), serde_json::json!(true));
    assert!(serde_json::from_value::<Profile>(unknown).is_err());
}
#[tokio::test]
async fn actual_tls_mismatched_profile_refuses_before_udp_or_hint() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let p = profile().await;
    let mut other = p.clone();
    other.resource_sha256 = [2; 32];
    let (a, b) = tokio::io::duplex(4096);
    let origin = Instant::now();
    let end = origin + Duration::from_secs(3);
    let (sent, received) = tokio::join!(
        send_once(&client, &None, a, p, Zeroizing::new(vec![7]), origin, end),
        receive_once(&server, &None, b, other, origin, end)
    );
    assert!(sent.is_err());
    let failure = received.err().unwrap();
    assert_eq!(failure.phase, "paired_admission");
    assert_eq!(failure.confirmed_prefix.delivered_packets, 0);
    assert!(!failure.confirmed_prefix.collector_started);
}
#[tokio::test]
async fn actual_certificate_refusal_preserves_safe_failed_prefix() {
    let mut f = fixture();
    f.server.allowed_client_sha256 = vec!["00".repeat(32)];
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let p = profile().await;
    let application = UdpSocket::bind(p.sender_application_peer).await.unwrap();
    application
        .connect(p.sender_application_bind)
        .await
        .unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (a, b) = tokio::io::duplex(4096);
    let origin = Instant::now();
    let end = origin + Duration::from_secs(3);
    let mut producer = OwnedTask(Some(tokio::spawn(application_source(
        application,
        ready_rx,
        end,
    ))));
    let (sent, received) = tokio::join!(
        send_once_with_ready(
            &client,
            &None,
            a,
            p.clone(),
            Zeroizing::new(vec![7]),
            ApplicationControl {
                origin,
                end,
                ready: Some(Box::new(move |ready| {
                    ready_tx.send(ready).ok();
                })),
            }
        ),
        receive_once(&server, &None, b, p.clone(), origin, end)
    );
    let sent = sent.err().unwrap();
    assert!(!sent.confirmed_prefix.collector_started);
    assert_eq!(sent.confirmed_prefix.sent_packets, 0);
    assert_eq!(
        producer.finish(end).await,
        (0, Some(io::ErrorKind::BrokenPipe))
    );
    // The failed producer is joined and owns no lingering application socket.
    let _released = UdpSocket::bind(p.sender_application_peer).await.unwrap();
    let failure = received.err().unwrap();
    assert_eq!(failure.error_kind, "PermissionDenied");
    assert!(!failure.accepted_delivery_complete);
    assert_eq!(failure.confirmed_prefix.delivered_packets, 0);
}
#[tokio::test]
async fn original_deadline_stalled_peer_and_no_new_socket_work() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let p = profile().await;
    let (a, _held) = tokio::io::duplex(8);
    let origin = Instant::now();
    let end = origin + Duration::from_millis(20);
    let failure = send_once(&client, &None, a, p, Zeroizing::new(vec![7]), origin, end)
        .await
        .err()
        .unwrap();
    assert_eq!(failure.error_kind, "TimedOut");
    assert!(!failure.confirmed_prefix.collector_started);
    assert_eq!(failure.confirmed_prefix.sent_packets, 0);
}
// Reach the real authenticated ARMED state without a release worker or a
// fabricated timing source. Each run derives the genuine TLS exporter book.
async fn armed_receiver_refusal(malformed_metadata: bool) -> (Failure, Profile) {
    armed_receiver_refusal_case(malformed_metadata, false).await
}

async fn armed_receiver_refusal_case(
    malformed_metadata: bool,
    early_packet: bool,
) -> (Failure, Profile) {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let p = profile().await;
    let (a, b) = tokio::io::duplex(4096);
    let origin = Instant::now();
    let end = origin + Duration::from_secs(10);
    let peer = async {
        let mut stream = client.connect(a).await.unwrap();
        let descriptor = p.descriptor().unwrap();
        stream.write_all(ADMISSION).await.unwrap();
        stream.write_all(&descriptor).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), ACCEPT);
        let seed = stream
            .get_ref()
            .1
            .export_keying_material(Zeroizing::new([0; 32]), EXPORTER_LABEL, Some(&descriptor))
            .unwrap();
        let book = Prepared::new(p.timing.clone(), seed, end).unwrap();
        stream.write_all(&book.digest()).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), ACCEPT);
        for _ in 0..CLOCK_SYNC_ROUNDS {
            stream.write_u64(elapsed(origin).unwrap()).await.unwrap();
            stream.flush().await.unwrap();
            let _b1 = stream.read_u64().await.unwrap();
            let _b2 = stream.read_u64().await.unwrap();
        }
        let start = elapsed(origin).unwrap() + 200_000_000;
        stream.write_u64(start).await.unwrap();
        stream.write_u64(start).await.unwrap();
        stream.write_u64(0).await.unwrap();
        stream.flush().await.unwrap();
        assert_eq!(stream.read_u8().await.unwrap(), ARMED);
        if early_packet {
            // The authenticated peer supplies a real packet before the agreed
            // origin and then withholds metadata. The collector's original
            // clock refusal must terminate the exchange, not a later TLS EOF.
            let packet = UdpSocket::bind(p.sender_packet_bind).await.unwrap();
            packet
                .send_to(b"early original", p.receiver_packet_bind)
                .await
                .unwrap();
            assert!(stream.read_u8().await.is_err());
            return;
        }
        if malformed_metadata {
            // Authenticated bytes, original fixed public size, wrong header.
            stream
                .write_all(&vec![0; p.metadata_size().unwrap()])
                .await
                .unwrap();
            stream.flush().await.unwrap();
        }
        stream.shutdown().await.unwrap();
    };
    let (_, received) = timeout_at(end, async {
        tokio::join!(
            peer,
            receive_once(&server, &None, b, p.clone(), origin, end)
        )
    })
    .await
    .unwrap();
    (received.err().expect("original peer refusal"), p)
}

async fn assert_failed_collector_retired(failure: &Failure, p: &Profile) {
    assert!(!failure.accepted_delivery_complete);
    assert!(failure.confirmed_prefix.collector_started);
    assert!(failure.confirmed_prefix.collector_abort_requested);
    assert!(failure.confirmed_prefix.collector_joined);
    assert_eq!(failure.confirmed_prefix.delivered_packets, 0);
    // Successful abort request alone cannot satisfy either actual bind.
    let _packet = UdpSocket::bind(p.receiver_packet_bind).await.unwrap();
    let _application = UdpSocket::bind(p.receiver_application_bind).await.unwrap();
}

#[tokio::test]
async fn actual_armed_tls_eof_preserves_error_and_joins_failed_collector() {
    let (failure, p) = armed_receiver_refusal(false).await;
    assert_eq!(failure.phase, "external_io");
    assert_eq!(failure.error_kind, "UnexpectedEof");
    assert_failed_collector_retired(&failure, &p).await;
}

#[tokio::test]
async fn actual_armed_bad_metadata_preserves_error_and_joins_failed_collector() {
    let (failure, p) = armed_receiver_refusal(true).await;
    assert_eq!(failure.phase, "metadata_frame");
    assert_eq!(failure.error_kind, "InvalidData");
    assert_failed_collector_retired(&failure, &p).await;
}

#[tokio::test]
async fn actual_armed_early_packet_without_metadata_preserves_collector_clock_refusal() {
    let (failure, p) = armed_receiver_refusal_case(false, true).await;
    assert_eq!(failure.phase, "clock_before_origin");
    assert_eq!(failure.error_kind, "InvalidData");
    assert_failed_collector_retired(&failure, &p).await;
}

struct OwnedTask<T>(Option<tokio::task::JoinHandle<T>>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        if let Some(task) = &self.0 {
            task.abort();
        }
    }
}
impl<T> OwnedTask<T> {
    async fn finish(&mut self, end: Instant) -> T {
        let task = self.0.as_mut().unwrap();
        let value = timeout_at(end, task).await.unwrap().unwrap();
        self.0.take();
        value
    }
}

// Cooperative fixture input starts only after the actual sender admits it.
// Readiness cancellation must remain a typed zero-input outcome, so it cannot
// replace the original TLS/admission refusal with a secondary task panic.
async fn application_source(
    application: UdpSocket,
    ready_rx: tokio::sync::oneshot::Receiver<ApplicationReady>,
    end: Instant,
) -> (u64, Option<io::ErrorKind>) {
    application_source_with_ready_buffer(application, ready_rx, end, false).await
}

async fn application_source_with_ready_buffer(
    application: UdpSocket,
    ready_rx: tokio::sync::oneshot::Receiver<ApplicationReady>,
    end: Instant,
    buffer_after_ready: bool,
) -> (u64, Option<io::ErrorKind>) {
    let ready = match timeout_at(end, ready_rx).await {
        Ok(Ok(ready)) => ready,
        Ok(Err(_)) => return (0, Some(io::ErrorKind::BrokenPipe)),
        Err(_) => return (0, Some(io::ErrorKind::TimedOut)),
    };
    // The positive queue test must supply genuine UDP input after authenticated
    // READY, with enough original-clock lead to survive host timer granularity.
    // It still sends through the same application socket; no queue is injected.
    let first = if buffer_after_ready {
        Instant::now()
    } else {
        ready.start
    };
    let mut interval = tokio::time::interval_at(first, Duration::from_millis(2));
    interval.set_missed_tick_behavior(if buffer_after_ready {
        tokio::time::MissedTickBehavior::Burst
    } else {
        tokio::time::MissedTickBehavior::Skip
    });
    let mut count = 0u64;
    loop {
        tokio::select! {
            biased;
            _ = sleep_until(end) => return (count, Some(io::ErrorKind::TimedOut)),
            _ = sleep_until(ready.covers_until) => return (count, None),
            _ = interval.tick() => {
                match application.send(&count.to_be_bytes()).await {
                    Ok(8) => count += 1,
                    Ok(_) => return (count, Some(io::ErrorKind::WriteZero)),
                    Err(error) => return (count, Some(error.kind())),
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn cooperative_source_readiness_deadline_has_no_input_and_releases_socket() {
    let application = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = application.local_addr().unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let end = Instant::now() + Duration::from_millis(10);
    assert_eq!(
        application_source(application, ready_rx, end).await,
        (0, Some(io::ErrorKind::TimedOut))
    );
    assert!(ready_tx.is_closed());
    let _released = UdpSocket::bind(address).await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn cooperative_source_closed_window_never_emits_the_first_tick() {
    let application = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let start = Instant::now();
    ready_tx
        .send(ApplicationReady {
            start,
            covers_until: start,
        })
        .ok()
        .unwrap();
    assert_eq!(
        application_source(application, ready_rx, start + Duration::from_secs(1)).await,
        (0, None)
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_fresh_tls_udp_timing_success_or_typed_failure_retains_owned_prefix() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let p = profile().await;
    let application = UdpSocket::bind(p.sender_application_peer).await.unwrap();
    application
        .connect(p.sender_application_bind)
        .await
        .unwrap();
    let sink = UdpSocket::bind(p.receiver_application_peer).await.unwrap();
    sink.connect(p.receiver_application_bind).await.unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<ApplicationReady>();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
    let observed_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let app_progress = std::sync::Arc::new(tokio::sync::Notify::new());
    let consumer_count = observed_count.clone();
    let consumer_progress = app_progress.clone();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(12);
    // This source is an actual owned deterministic fixture, NOT evidence of a
    // legitimate Poisson process or a real M/M/1 service law.
    let mut producer = OwnedTask(Some(tokio::spawn(application_source(
        application,
        ready_rx,
        end,
    ))));
    let mut consumer = OwnedTask(Some(tokio::spawn(async move {
        let mut data = Vec::new();
        let mut buffer = [0; 128];
        loop {
            tokio::select! {biased;_=&mut done_rx=>break,_=sleep_until(end)=>panic!("application fixture deadline"),read=sink.recv(&mut buffer)=>{let n=read.unwrap();assert_eq!(n,8);data.push(u64::from_be_bytes(buffer[..8].try_into().unwrap()));consumer_count.store(data.len(),std::sync::atomic::Ordering::Release);consumer_progress.notify_one();}}
        }
        data
    })));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a, b) = tokio::join!(
        tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let a = a.unwrap();
    let b = b.unwrap().0;
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    let (sent, received) = tokio::join!(
        send_once_with_ready(
            &client,
            &None,
            a,
            p.clone(),
            Zeroizing::new(b"z".to_vec()),
            ApplicationControl {
                origin,
                end,
                ready: Some(Box::new(move |ready| {
                    ready_tx.send(ready).ok();
                }))
            }
        ),
        receive_once(&server, &None, b, p.clone(), origin, end)
    );
    let (sent, received) = match (sent, received) {
        (Ok(sent), Ok(received)) => (sent, received),
        (left, right) => {
            // Genuine scheduling/service/decoder failures are not positive
            // message delivery. Preserve both typed prefixes and producer I/O.
            if let Err(failure) = &left {
                println!(
                    "actual_sender_refusal={}",
                    serde_json::to_string(failure).unwrap()
                );
            }
            if let Err(failure) = &right {
                println!(
                    "actual_receiver_refusal={}",
                    serde_json::to_string(failure).unwrap()
                );
            }
            let (offered, producer_terminal) = producer.finish(end).await;
            println!("actual_cooperative_producer_count={offered} terminal={producer_terminal:?}");
            done_tx.send(()).ok();
            let originals = consumer.finish(end).await;
            if let Err(failure) = left {
                assert!(!failure.accepted_delivery_complete);
                assert!(
                    failure.confirmed_prefix.sent_packets
                        <= failure.confirmed_prefix.accepted_packets
                );
                assert_eq!(
                    failure.confirmed_prefix.retained_packets,
                    failure.confirmed_prefix.accepted_packets
                        - failure.confirmed_prefix.sent_packets
                );
                assert!(offered as usize >= failure.confirmed_prefix.accepted_packets);
            }
            let failure = right
                .err()
                .expect("a sender failure must never expose an authenticated control hint");
            assert!(!failure.accepted_delivery_complete);
            assert!(
                failure.confirmed_prefix.delivered_packets
                    <= failure.confirmed_prefix.received_packets
            );
            assert!(originals.iter().copied().eq(0..originals.len() as u64));
            // Exact owned Drop completes port release; no name/global cleanup.
            tokio::task::yield_now().await;
            timeout_at(end, async {
                loop {
                    match UdpSocket::bind(p.receiver_packet_bind).await {
                        Ok(socket) => {
                            drop(socket);
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                            tokio::task::yield_now().await
                        }
                        Err(e) => panic!("fixture port refusal: {:?}", e.kind()),
                    }
                }
            })
            .await
            .unwrap();
            return;
        }
    };
    assert_eq!(received.payload.as_slice(), b"z");
    assert!(sent.timing_control_authenticated);
    assert!(received.receipt.collector_terminal);
    assert!(!received.receipt.observations.service_model_verified);
    assert!(
        !received
            .receipt
            .application_origin_and_unique_sequence_verified
    );
    let (offered, producer_terminal) = producer.finish(end).await;
    assert_eq!(producer_terminal, None);
    let expected = sent.observations.accepted_packets;
    assert_eq!(expected, sent.observations.sent_packets);
    assert!(offered as usize >= expected);
    assert_eq!(received.receipt.observations.delivered_packets, expected);
    // Give the app receiver a real packet-count barrier before stopping it.
    // Fixed public protocol finalization normally leaves this queue drained;
    // this extra fixture observation is not a wire delivery theorem.
    timeout_at(end, async {
        loop {
            let notified = app_progress.notified();
            if observed_count.load(std::sync::atomic::Ordering::Acquire) == expected {
                break;
            }
            notified.await;
        }
    })
    .await
    .unwrap();
    done_tx.send(()).ok();
    let originals = consumer.finish(end).await;
    assert_eq!(originals.len(), expected);
    assert!(originals.iter().copied().eq(0..expected as u64));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn actual_fresh_tls_udp_service_queue_decodes_authenticated_message() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let p = profile().await;
    let application = UdpSocket::bind(p.sender_application_peer).await.unwrap();
    application
        .connect(p.sender_application_bind)
        .await
        .unwrap();
    let sink = UdpSocket::bind(p.receiver_application_peer).await.unwrap();
    sink.connect(p.receiver_application_bind).await.unwrap();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<ApplicationReady>();
    let (done_tx, mut done_rx) = tokio::sync::oneshot::channel::<()>();
    let observed_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let app_progress = std::sync::Arc::new(tokio::sync::Notify::new());
    let consumer_count = observed_count.clone();
    let consumer_progress = app_progress.clone();
    let origin = Instant::now();
    let end = origin + Duration::from_secs(12);
    // This source is an actual owned deterministic fixture, NOT evidence of a
    // legitimate Poisson process or a real M/M/1 service law.
    let mut producer = OwnedTask(Some(tokio::spawn(application_source_with_ready_buffer(
        application,
        ready_rx,
        end,
        true,
    ))));
    let mut consumer = OwnedTask(Some(tokio::spawn(async move {
        let mut data = Vec::new();
        let mut buffer = [0; 128];
        loop {
            tokio::select! {biased;_=&mut done_rx=>break,_=sleep_until(end)=>panic!("application fixture deadline"),read=sink.recv(&mut buffer)=>{let n=read.unwrap();assert_eq!(n,8);data.push(u64::from_be_bytes(buffer[..8].try_into().unwrap()));consumer_count.store(data.len(),std::sync::atomic::Ordering::Release);consumer_progress.notify_one();}}
        }
        data
    })));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a, b) = tokio::join!(
        tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    let a = a.unwrap();
    let b = b.unwrap().0;
    a.set_nodelay(true).unwrap();
    b.set_nodelay(true).unwrap();
    let (sent, received) = tokio::join!(
        send_once_with_ready(
            &client,
            &None,
            a,
            p.clone(),
            Zeroizing::new(b"z".to_vec()),
            ApplicationControl {
                origin,
                end,
                ready: Some(Box::new(move |ready| {
                    ready_tx.send(ready).ok();
                }))
            }
        ),
        receive_once(&server, &None, b, p.clone(), origin, end)
    );
    let (sent, received) = match (sent, received) {
        (Ok(sent), Ok(received)) => (sent, received),
        (left, right) => {
            // Genuine scheduling/service/decoder failures are not positive
            // message delivery. Preserve both typed prefixes before fixture cleanup.
            if let Err(failure) = &left {
                println!(
                    "actual_sender_refusal={}",
                    serde_json::to_string(failure).unwrap()
                );
            }
            if let Err(failure) = &right {
                println!(
                    "actual_receiver_refusal={}",
                    serde_json::to_string(failure).unwrap()
                );
            }
            let (offered, producer_terminal) = producer.finish(end).await;
            println!("actual_cooperative_producer_count={offered} terminal={producer_terminal:?}");
            done_tx.send(()).ok();
            let originals = consumer.finish(end).await;
            if let Err(failure) = left {
                assert!(!failure.accepted_delivery_complete);
                assert!(
                    failure.confirmed_prefix.sent_packets
                        <= failure.confirmed_prefix.accepted_packets
                );
                assert_eq!(
                    failure.confirmed_prefix.retained_packets,
                    failure.confirmed_prefix.accepted_packets
                        - failure.confirmed_prefix.sent_packets
                );
                assert!(offered as usize >= failure.confirmed_prefix.accepted_packets);
            }
            let failure = right
                .err()
                .expect("a sender failure must never expose an authenticated control hint");

            assert!(!failure.accepted_delivery_complete);
            assert!(
                failure.confirmed_prefix.delivered_packets
                    <= failure.confirmed_prefix.received_packets
            );
            assert!(originals.iter().copied().eq(0..originals.len() as u64));
            // Exact owned Drop completes port release; no name/global cleanup.
            tokio::task::yield_now().await;
            timeout_at(end, async {
                loop {
                    match UdpSocket::bind(p.receiver_packet_bind).await {
                        Ok(socket) => {
                            drop(socket);
                            break;
                        }
                        Err(e) if e.kind() == io::ErrorKind::AddrInUse => {
                            tokio::task::yield_now().await
                        }
                        Err(e) => panic!("fixture port refusal: {:?}", e.kind()),
                    }
                }
            })
            .await
            .unwrap();
            panic!("fresh TLS positive delivery refused; typed evidence preserved above");
        }
    };
    assert!(sent.observations.service_queue_contract_v2);
    assert!(sent.observations.release_thread_joined);
    println!(
        "fresh_tls_service_queue_observations={}",
        serde_json::to_string(&sent.observations).unwrap()
    );
    assert_eq!(received.payload.as_slice(), b"z");
    assert!(sent.timing_control_authenticated);
    assert!(received.receipt.collector_terminal);
    assert!(!received.receipt.observations.service_model_verified);
    assert!(
        !received
            .receipt
            .application_origin_and_unique_sequence_verified
    );
    let (offered, producer_terminal) = producer.finish(end).await;
    assert_eq!(producer_terminal, None);
    let expected = sent.observations.accepted_packets;
    assert_eq!(expected, sent.observations.sent_packets);
    assert!(offered as usize >= expected);
    assert_eq!(received.receipt.observations.delivered_packets, expected);
    // Give the app receiver a real packet-count barrier before stopping it.
    // Fixed public protocol finalization normally leaves this queue drained;
    // this extra fixture observation is not a wire delivery theorem.
    timeout_at(end, async {
        loop {
            let notified = app_progress.notified();
            if observed_count.load(std::sync::atomic::Ordering::Acquire) == expected {
                break;
            }
            notified.await;
        }
    })
    .await
    .unwrap();
    done_tx.send(()).ok();
    let originals = consumer.finish(end).await;
    assert_eq!(originals.len(), expected);
    assert!(originals.iter().copied().eq(0..expected as u64));
}

async fn scripted_clock_rounds(
    samples: [(u64, u64, u64, u64); CLOCK_SYNC_ROUNDS],
) -> (io::Result<(u64, i128)>, usize) {
    let (mut sender, mut peer) = tokio::io::duplex(128);
    let mut clock_call = 0;
    let sender = async {
        sender_clock_sync(
            &mut sender,
            || {
                let value = if clock_call % 2 == 0 {
                    samples[clock_call / 2].0
                } else {
                    samples[clock_call / 2].3
                };
                clock_call += 1;
                Ok(value)
            },
            10_000_000,
        )
        .await
    };
    let peer = async {
        let mut rounds = 0;
        for (t0, b1, b2, _) in samples {
            assert_eq!(peer.read_u64().await.unwrap(), t0);
            peer.write_u64(b1).await.unwrap();
            peer.write_u64(b2).await.unwrap();
            peer.flush().await.unwrap();
            rounds += 1;
        }
        rounds
    };
    tokio::join!(sender, peer)
}

#[tokio::test]
async fn clock_sync_runs_all_five_rounds_after_slow_first_and_keeps_cap() {
    let samples = [
        (0, 2_000_000, 2_000_000, 30_000_000),
        (40_000_000, 41_000_000, 41_000_000, 42_000_000),
        (50_000_000, 53_000_000, 53_000_000, 76_000_000),
        (80_000_000, 83_000_000, 83_000_000, 104_000_000),
        (110_000_000, 113_000_000, 113_000_000, 130_000_000),
    ];
    let (selected, rounds) = scripted_clock_rounds(samples).await;
    assert_eq!(rounds, CLOCK_SYNC_ROUNDS);
    assert_eq!(selected.unwrap(), (1_000_000, 0));
    let all_bad = [
        samples[0],
        (40_000_000, 41_000_000, 41_000_000, 70_000_000),
        (80_000_000, 83_000_000, 83_000_000, 106_000_000),
        (110_000_000, 113_000_000, 113_000_000, 134_000_000),
        (140_000_000, 143_000_000, 143_000_000, 162_000_000),
    ];
    let (failure, rounds) = scripted_clock_rounds(all_bad).await;
    assert_eq!(rounds, CLOCK_SYNC_ROUNDS);
    assert_eq!(failure.unwrap_err().kind(), io::ErrorKind::InvalidData);
}

#[test]
fn malformed_clock_samples_refuse() {
    for (t0, b1, b2, t3) in [(5, 1, 2, 4), (0, 4, 3, 5), (0, 1, 9, 3)] {
        let failure = clock_sample(t0, b1, b2, t3).err().unwrap();
        assert_eq!(failure.kind(), io::ErrorKind::InvalidData);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn actual_authorized_pending_control_lease_revocation_releases_only_its_owner() {
    use crate::secure_channel::registry::{
        publish_snapshot, unix_now, DeviceRecord, DeviceRegistry,
    };
    let mut f = fixture();
    let now = unix_now().unwrap();
    let path = f._dir.path().join("registry.json");
    let mut registry = DeviceRegistry::new(now, 60).unwrap();
    registry.devices.push(DeviceRecord {
        device_id: "poisson-owned-fixture".into(),
        certificate_sha256: f.server.allowed_client_sha256[0].clone(),
        not_after_unix_secs: now + 60,
        revoked: false,
    });
    publish_snapshot(&path, &registry).unwrap();
    f.server.allowed_client_sha256.clear();
    f.server.device_registry = Some(path.clone());
    let server = Server::load(&f.server).unwrap();
    let _watcher = server.start_registry_watcher().unwrap();
    let baseline = server.handshakes.permits.available_permits();
    let client = Client::load(&f.client).unwrap();
    let p = profile().await;
    let (a, b) = tokio::io::duplex(1024);
    let origin = Instant::now();
    let end = origin + Duration::from_secs(4);
    let owned_server = server.clone();
    let admitted = p.clone();
    let mut receiver = OwnedTask(Some(tokio::spawn(async move {
        receive_once(&owned_server, &None, b, admitted, origin, end).await
    })));
    let mut unrelated = OwnedTask(Some(tokio::spawn(std::future::pending::<()>())));
    let mut stream = client.connect(a).await.unwrap();
    stream.write_all(ADMISSION).await.unwrap();
    stream.write_all(&p.descriptor().unwrap()).await.unwrap();
    stream.flush().await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), ACCEPT);
    assert_eq!(server.handshakes.permits.available_permits(), baseline - 1);
    registry.generation += 1;
    registry.devices[0].revoked = true;
    publish_snapshot(&path, &registry).unwrap();
    let failure = receiver.finish(end).await.err().unwrap();
    assert_eq!(failure.error_kind, "PermissionDenied");
    assert_eq!(failure.confirmed_prefix.accepted_packets, 0);
    assert!(!failure.confirmed_prefix.collector_started);
    assert!(!failure.accepted_delivery_complete);
    assert_eq!(server.handshakes.permits.available_permits(), baseline);
    assert!(timeout_at(end, stream.read_u8()).await.unwrap().is_err());
    assert!(!unrelated.0.as_ref().unwrap().is_finished());
    let task = unrelated.0.take().unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
}
