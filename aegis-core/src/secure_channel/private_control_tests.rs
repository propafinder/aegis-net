use super::*;
use crate::secure_channel::*;
use sha2::{Digest, Sha256};

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

fn cover(capacity: usize) -> ControlProfile {
    ControlProfile::Cover(
        CoverModel::new(
            vec![vec![65], vec![66]],
            vec![1, 1],
            1,
            capacity,
            Duration::from_secs(1),
        )
        .unwrap(),
    )
}
fn schedule() -> ControlProfile {
    ControlProfile::BinarySchedule(
        ScheduleProfile::new(
            3,
            32,
            Duration::from_millis(2),
            Duration::from_secs(1),
            2,
            1,
            8,
            1,
        )
        .unwrap(),
    )
}
async fn tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (a, b) = tokio::join!(
        tokio::net::TcpStream::connect(listener.local_addr().unwrap()),
        listener.accept()
    );
    (a.unwrap(), b.unwrap().0)
}
#[tokio::test]
async fn actual_tls_tcp_cover_peer_decode_and_private_output() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tcp_pair().await;
    let payload = b"private control message";
    let (sent, received) = tokio::join!(
        send_once(
            &client,
            &None,
            a,
            cover(32),
            ControlInput(vec![Zeroizing::new(payload.to_vec())]),
            Duration::from_secs(3)
        ),
        receive_once(&server, &None, b, cover(32), Duration::from_secs(3))
    );
    assert!(sent.unwrap().peer_decoded);
    let path = f._dir.path().join("decoded");
    received.unwrap().save_private_new(&path).unwrap();
    assert!(secret_file::read(&path, 256).unwrap().as_slice() == payload);
    assert!(secret_file::write_private_new(&path, b"overwrite").is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[tokio::test]
async fn actual_tls_schedule_entire_batch_dummy_data_and_accounting() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tcp_pair().await;
    let input = ControlInput(vec![
        Zeroizing::new(b"one".to_vec()),
        Zeroizing::new(vec![]),
        Zeroizing::new(b"three".to_vec()),
    ]);
    let (sent, received) = tokio::join!(
        send_once(&client, &None, a, schedule(), input, Duration::from_secs(3)),
        receive_once(&server, &None, b, schedule(), Duration::from_secs(3))
    );
    assert_eq!(sent.unwrap().schedule.unwrap().accounting.releases, 3);
    let received = received.unwrap();
    assert_eq!(received.cells(), 3);
    assert!(received.payloads[0].as_slice() == b"one");
    assert!(received.payloads[1].is_empty());
    assert!(received.payloads[2].as_slice() == b"three");
}
#[tokio::test]
async fn mismatched_public_profile_refused_before_payload() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tokio::io::duplex(512);
    let (sent, received) = tokio::join!(
        send_once(
            &client,
            &None,
            a,
            cover(32),
            ControlInput(vec![Zeroizing::new(b"secret".to_vec())]),
            Duration::from_secs(2)
        ),
        receive_once(&server, &None, b, cover(31), Duration::from_secs(2))
    );
    assert!(sent.is_err());
    assert_eq!(received.err().unwrap().kind, io::ErrorKind::InvalidInput);
}
#[tokio::test]
async fn actual_certificate_allowlist_refusal() {
    let mut f = fixture();
    f.server.allowed_client_sha256 = vec!["00".repeat(32)];
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tokio::io::duplex(512);
    let (sent, received) = tokio::join!(
        send_once(
            &client,
            &None,
            a,
            cover(32),
            ControlInput(vec![Zeroizing::new(vec![1])]),
            Duration::from_secs(2)
        ),
        receive_once(&server, &None, b, cover(32), Duration::from_secs(2))
    );
    assert!(sent.is_err());
    assert_eq!(
        received.err().unwrap().kind,
        io::ErrorKind::PermissionDenied
    );
}
#[tokio::test]
async fn deadline_owns_handshake_and_refuses_stalled_peer() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let (a, _held) = tokio::io::duplex(8);
    let result = send_once(
        &client,
        &None,
        a,
        cover(32),
        ControlInput(vec![Zeroizing::new(vec![1])]),
        Duration::from_millis(10),
    )
    .await;
    assert_eq!(result.err().unwrap().kind, io::ErrorKind::TimedOut);
}
#[test]
fn fixed_admission_and_operator_wire_budget_refusals() {
    assert_eq!(cover(32).admission().len(), 36);
    let large = ControlProfile::Cover(
        CoverModel::new(
            vec![vec![65; 32], vec![66; 32]],
            vec![1, 1],
            1,
            64,
            Duration::from_secs(1),
        )
        .unwrap(),
    );
    assert!(large.validate().is_err());
    assert!(preflight(&cover(32), &None, Duration::from_secs(61)).is_err());
    let shaping = crate::carrier_runtime::PrivacySettings {
        payload_bytes: 32,
        cadence_ms: 1,
        buffer_bytes: 128,
        max_wire_bytes: 4096,
        io_timeout_ms: 100,
        session_timeout_ms: 100,
        max_queue_delay_ms: 10,
        poisson_pacing: None,
        net_shaper: None,
        adaptive_channel: None,
        arrival_envelope: None,
        cover_stream: None,
        bit_traps: None,
        liu_channel: None,
    };
    assert!(preflight(&cover(32), &Some(shaping), Duration::from_secs(1)).is_err());
}
#[tokio::test]
async fn fresh_tls_exporter_domain_and_connection_separation() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let mut previous: Option<Zeroizing<Vec<u8>>> = None;
    for _ in 0..2 {
        let (a, b) = tokio::io::duplex(512);
        let (c, s) = tokio::join!(client.connect(a), server.accept_with_lease(b));
        let c = c.unwrap();
        let (s, _lease) = s.unwrap();
        let ctx = context(&cover(32).admission());
        let left = c
            .get_ref()
            .1
            .export_keying_material(
                Zeroizing::new(vec![0; 32]),
                b"aegis.control.cover.key.v1",
                Some(&ctx),
            )
            .unwrap();
        let right = s
            .get_ref()
            .1
            .export_keying_material(
                Zeroizing::new(vec![0; 32]),
                b"aegis.control.cover.key.v1",
                Some(&ctx),
            )
            .unwrap();
        assert!(left.as_slice() == right.as_slice());
        let separated = c
            .get_ref()
            .1
            .export_keying_material(
                Zeroizing::new(vec![0; 32]),
                b"aegis.control.cover.pad.v1",
                Some(&ctx),
            )
            .unwrap();
        assert!(left.as_slice() != separated.as_slice());
        if let Some(old) = previous {
            assert!(left.as_slice() != old.as_slice());
        }
        previous = Some(left);
    }
}
#[test]
fn private_input_exact_slot_format_and_no_symlink_or_overwrite() {
    let d = tempfile::tempdir().unwrap();
    let p = d.path().join("input");
    secret_file::write_private_new(&p, b"\x00\x01x\x00\x00\x00\x01y").unwrap();
    assert_eq!(
        ControlInput::read_private(&schedule(), &p).unwrap().0.len(),
        3
    );
    let bad = d.path().join("bad");
    secret_file::write_private_new(&bad, b"\x00\x01x").unwrap();
    assert!(ControlInput::read_private(&schedule(), &bad).is_err());
    #[cfg(unix)]
    {
        let link = d.path().join("link");
        std::os::unix::fs::symlink(&p, &link).unwrap();
        assert!(ControlInput::read_private(&cover(32), &link).is_err());
    }
}

#[tokio::test]
async fn completed_spending_retained_when_peer_omits_final_ack() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tokio::io::duplex(512);
    let peer = async {
        let (mut stream, _lease) = server.accept_with_lease(b).await.unwrap();
        let mut admission = [0; ADMISSION_BYTES];
        stream.read_exact(&mut admission).await.unwrap();
        assert!(admission == schedule().admission());
        stream.write_u8(ACCEPT).await.unwrap();
        stream.flush().await.unwrap();
        let ctx = context(&admission);
        let codec = codec(schedule(), |label, len| {
            stream
                .get_ref()
                .1
                .export_keying_material(Zeroizing::new(vec![0; len]), label, Some(&ctx))
                .map_err(|_| super::invalid())
        })
        .unwrap();
        match codec {
            Codec::Schedule(batch) => {
                assert_eq!(batch.receive(&mut stream).await.unwrap().payloads.len(), 3);
            }
            _ => panic!("wrong test mode"),
        }
        // Drop this exact owned TLS stream without a completion marker.
    };
    let input = ControlInput(vec![
        Zeroizing::new(vec![1]),
        Zeroizing::new(vec![]),
        Zeroizing::new(vec![2]),
    ]);
    let (result, ()) = tokio::join!(
        send_once(&client, &None, a, schedule(), input, Duration::from_secs(3)),
        peer
    );
    let failure = result.err().unwrap();
    assert_eq!(failure.completed_schedule.unwrap().accounting.releases, 3);
    assert!(!failure.schedule_accounting_unknown);
}
#[tokio::test]
async fn outer_deadline_reports_unknown_never_zero_schedule_spending() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let (a, _held) = tokio::io::duplex(8);
    let input = ControlInput(vec![
        Zeroizing::new(vec![]),
        Zeroizing::new(vec![]),
        Zeroizing::new(vec![]),
    ]);
    let failure = send_once(
        &client,
        &None,
        a,
        schedule(),
        input,
        Duration::from_millis(10),
    )
    .await
    .err()
    .unwrap();
    assert!(failure.schedule_accounting_unknown);
    assert!(failure.schedule.is_none());
    assert!(failure.completed_schedule.is_none());
}
#[tokio::test]
async fn oversized_private_cell_refused_before_handshake() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let (a, _held) = tokio::io::duplex(8);
    let failure = send_once(
        &client,
        &None,
        a,
        cover(1),
        ControlInput(vec![Zeroizing::new(vec![1, 2])]),
        Duration::from_secs(1),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(failure.kind, io::ErrorKind::InvalidInput);
}

struct DropObserved {
    inner: tokio::io::DuplexStream,
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Drop for DropObserved {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}
impl AsyncRead for DropObserved {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for DropObserved {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[tokio::test]
async fn canceled_owned_task_drops_only_its_carrier() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let (a, _peer) = tokio::io::duplex(8);
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = DropObserved {
        inner: a,
        dropped: dropped.clone(),
    };
    let (other, _other_peer) = tokio::io::duplex(8);
    let other_dropped = Arc::new(AtomicBool::new(false));
    let _unrelated = DropObserved {
        inner: other,
        dropped: other_dropped.clone(),
    };
    let task = tokio::spawn(async move {
        send_once(
            &client,
            &None,
            observed,
            cover(32),
            ControlInput(vec![Zeroizing::new(vec![1])]),
            Duration::from_secs(3),
        )
        .await
    });
    tokio::task::yield_now().await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert!(dropped.load(Ordering::SeqCst));
    assert!(!other_dropped.load(Ordering::SeqCst));
}
#[test]
fn exporter_refuses_before_completed_handshake() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let connection =
        rustls::ClientConnection::new(client.config.clone(), client.server_name.clone()).unwrap();
    assert!(connection
        .export_keying_material(
            Zeroizing::new(vec![0; 32]),
            b"aegis.control.cover.key.v1",
            Some(b"profile-and-direction")
        )
        .is_err());
}

#[cfg(unix)]
#[tokio::test]
async fn actual_registry_revocation_cancels_pending_authorized_control_and_releases_owner() {
    use crate::secure_channel::registry::{
        publish_snapshot, unix_now, DeviceRecord, DeviceRegistry,
    };
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let mut f = fixture();
    let now = unix_now().unwrap();
    let registry_path = f._dir.path().join("registry.json");
    let mut registry = DeviceRegistry::new(now, 60).unwrap();
    registry.devices.push(DeviceRecord {
        device_id: "control-test-device".into(),
        certificate_sha256: f.server.allowed_client_sha256[0].clone(),
        not_after_unix_secs: now + 60,
        revoked: false,
    });
    publish_snapshot(&registry_path, &registry).unwrap();
    f.server.allowed_client_sha256.clear();
    f.server.device_registry = Some(registry_path.clone());
    let server = Server::load(&f.server).unwrap();
    let _watcher = server.start_registry_watcher().unwrap();
    let client = Client::load(&f.client).unwrap();
    let baseline = server.handshakes.permits.available_permits();
    let (a, b) = tokio::io::duplex(512);
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = DropObserved {
        inner: b,
        dropped: dropped.clone(),
    };
    let receiver_server = server.clone();
    let receiver = tokio::spawn(async move {
        let profile = ControlProfile::Cover(
            CoverModel::new(
                vec![vec![65], vec![66]],
                vec![1, 1],
                1,
                32,
                Duration::from_secs(3),
            )
            .unwrap(),
        );
        receive_once(
            &receiver_server,
            &None,
            observed,
            profile,
            Duration::from_secs(4),
        )
        .await
    });
    let unrelated = tokio::spawn(std::future::pending::<()>());
    let mut stream = client.connect(a).await.unwrap();
    let agreed = ControlProfile::Cover(
        CoverModel::new(
            vec![vec![65], vec![66]],
            vec![1, 1],
            1,
            32,
            Duration::from_secs(3),
        )
        .unwrap(),
    );
    stream.write_all(&agreed.admission()).await.unwrap();
    stream.flush().await.unwrap();
    assert_eq!(stream.read_u8().await.unwrap(), ACCEPT);
    assert_eq!(server.handshakes.permits.available_permits(), baseline - 1);
    // Admission is complete; withhold all payload and revoke its live lease.
    registry.generation += 1;
    registry.devices[0].revoked = true;
    publish_snapshot(&registry_path, &registry).unwrap();
    let result = tokio::time::timeout(Duration::from_secs(4), receiver)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.err().unwrap().kind, io::ErrorKind::PermissionDenied);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(server.handshakes.permits.available_permits(), baseline);
    assert!(
        tokio::time::timeout(Duration::from_secs(1), stream.read_u8())
            .await
            .unwrap()
            .is_err()
    );
    assert!(!unrelated.is_finished());
    unrelated.abort();
    assert!(unrelated.await.unwrap_err().is_cancelled());
    assert!(!f._dir.path().join("decoded").exists());
}

#[tokio::test]
async fn actual_tls_general_imec_cover_roundtrip_and_profile_refusal() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let general = || {
        ControlProfile::Cover(
            CoverModel::new_general(
                vec![vec![65], vec![66], vec![67]],
                vec![4, 2, 1],
                1,
                256,
                Duration::from_secs(2),
            )
            .unwrap(),
        )
    };
    let (a, b) = tcp_pair().await;
    let (sent, received) = tokio::join!(
        send_once(
            &client,
            &None,
            a,
            general(),
            ControlInput(vec![Zeroizing::new(vec![9])]),
            Duration::from_secs(5)
        ),
        receive_once(&server, &None, b, general(), Duration::from_secs(5))
    );
    assert!(sent.is_ok());
    let received = received.unwrap();
    assert_eq!(received.payloads[0].as_slice(), [9]);
    let (a, b) = tcp_pair().await;
    let other = ControlProfile::Cover(
        CoverModel::new_general(
            vec![vec![65], vec![66], vec![67]],
            vec![4, 2, 1],
            1,
            257,
            Duration::from_secs(2),
        )
        .unwrap(),
    );
    let (sent, received) = tokio::join!(
        send_once(
            &client,
            &None,
            a,
            general(),
            ControlInput(vec![Zeroizing::new(vec![9])]),
            Duration::from_secs(5)
        ),
        receive_once(&server, &None, b, other, Duration::from_secs(5))
    );
    assert!(sent.is_err() && received.is_err());
}

// A complete authenticated peer ACK can arrive in a synchronously late poll.
// This is a controlled in-memory TLS regression, not a native timing guarantee.
#[tokio::test]
async fn original_private_control_cutoff_refuses_late_authenticated_ack() {
    use std::{
        pin::Pin,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
        task::{Context, Poll},
    };
    struct LateAckRead {
        inner: tokio::io::DuplexStream,
        ack: Arc<AtomicBool>,
    }
    impl AsyncRead for LateAckRead {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if self.ack.swap(false, Ordering::AcqRel) {
                std::thread::sleep(Duration::from_millis(150));
            }
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }
    impl AsyncWrite for LateAckRead {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.inner).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_shutdown(cx)
        }
    }
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tokio::io::duplex(8192);
    let ack = Arc::new(AtomicBool::new(false));
    let observed = LateAckRead {
        inner: a,
        ack: ack.clone(),
    };
    let peer = async {
        let mut stream = server.accept(b).await.unwrap();
        let mut admission = [0; ADMISSION_BYTES];
        stream.read_exact(&mut admission).await.unwrap();
        assert_eq!(admission, cover(32).admission());
        stream.write_u8(ACCEPT).await.unwrap();
        stream.flush().await.unwrap();
        let ctx = context(&admission);
        let codec = codec(cover(32), |label, len| {
            stream
                .get_ref()
                .1
                .export_keying_material(Zeroizing::new(vec![0; len]), label, Some(&ctx))
                .map_err(|_| super::invalid())
        })
        .unwrap();
        let Codec::Cover(record) = codec else {
            panic!("cover fixture")
        };
        assert_eq!(
            record.receive(&mut stream).await.unwrap().as_slice(),
            b"control"
        );
        ack.store(true, Ordering::Release);
        stream.write_u8(DECODED).await.unwrap();
        stream.flush().await.unwrap();
    };
    let (result, ()) = tokio::join!(
        send_once(
            &client,
            &None,
            observed,
            cover(32),
            ControlInput(vec![Zeroizing::new(b"control".to_vec())]),
            Duration::from_millis(100)
        ),
        peer
    );
    assert_eq!(result.unwrap_err().kind, io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn caller_original_expired_cutoff_refuses_before_tls_and_releases_carrier() {
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let baseline = server.handshakes.permits.available_permits();
    for receiver in [false, true] {
        let (inner, _held) = tokio::io::duplex(8);
        let dropped = Arc::new(AtomicBool::new(false));
        let wire = DropObserved {
            inner,
            dropped: dropped.clone(),
        };
        // The caller has already spent its entire establishment allowance.
        let end = tokio::time::Instant::now();
        let kind = if receiver {
            receive_once_until(&server, &None, wire, cover(32), end)
                .await
                .err()
                .unwrap()
                .kind
        } else {
            send_once_until(
                &client,
                &None,
                wire,
                cover(32),
                ControlInput(vec![Zeroizing::new(vec![1])]),
                end,
            )
            .await
            .unwrap_err()
            .kind
        };
        assert_eq!(kind, io::ErrorKind::TimedOut);
        assert!(dropped.load(Ordering::SeqCst));
        assert_eq!(server.handshakes.permits.available_permits(), baseline);
    }
    let (a, _held) = tokio::io::duplex(8);
    let result = send_once(
        &client,
        &None,
        a,
        cover(32),
        ControlInput(vec![Zeroizing::new(vec![1])]),
        Duration::MAX,
    )
    .await;
    assert_eq!(result.unwrap_err().kind, io::ErrorKind::InvalidInput);
}
