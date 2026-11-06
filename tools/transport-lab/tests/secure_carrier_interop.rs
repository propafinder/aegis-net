//! Real Aegis inner TLS over a bounded local ordered-message fixture.
//! Unix key-file custody only; no native WebRTC or production-adapter claim.
#![cfg(unix)]

use aegis_core::secure_channel::{
    read_open, write_open, AuthenticationFailure, Client, ClientSettings, OpenRequest, Server,
    ServerSettings, Transport,
};
use aegis_transport_lab::message_carrier::{MessageCarrier, MAX_FRAGMENT_BYTES};
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};

const SESSION_DEADLINE: Duration = Duration::from_secs(5);

struct Fixture {
    _dir: tempfile::TempDir,
    server: ServerSettings,
    allowed: Client,
    refused: Client,
    allowed_fingerprint: [u8; 32],
}

fn write_private(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
}

fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    write_private(&dir.path().join("ca.pem"), ca.pem().as_bytes());

    let mut identities = Vec::new();
    for (name, usage) in [
        ("inner.test", ExtendedKeyUsagePurpose::ServerAuth),
        ("allowed.test", ExtendedKeyUsagePurpose::ClientAuth),
        ("refused.test", ExtendedKeyUsagePurpose::ClientAuth),
    ] {
        let mut params = CertificateParams::new(vec![name.into()]).unwrap();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let cert = params.signed_by(&key, &ca, &ca_key).unwrap();
        let cert_path = dir.path().join(format!("{name}.pem"));
        let key_path = dir.path().join(format!("{name}.key"));
        write_private(&cert_path, cert.pem().as_bytes());
        write_private(&key_path, key.serialize_pem().as_bytes());
        identities.push((
            cert_path,
            key_path,
            <[u8; 32]>::from(Sha256::digest(cert.der().as_ref())),
        ));
    }
    let load_client = |index: usize| {
        Client::load(&ClientSettings {
            server_name: "inner.test".into(),
            server_ca: dir.path().join("ca.pem"),
            cert: identities[index].0.clone(),
            key: identities[index].1.clone(),
        })
        .unwrap()
    };
    Fixture {
        server: ServerSettings {
            cert: identities[0].0.clone(),
            key: identities[0].1.clone(),
            client_ca: dir.path().join("ca.pem"),
            allowed_client_sha256: vec![hex::encode(identities[1].2)],
            device_registry: None,
            admission: Default::default(),
            handshake_timeout_ms: 1000,
            idle_timeout_ms: 1000,
        },
        allowed: load_client(1),
        refused: load_client(2),
        allowed_fingerprint: identities[1].2,
        _dir: dir,
    }
}

fn open_request() -> OpenRequest {
    OpenRequest {
        version: 1,
        host: "disposable-target.test".into(),
        port: 443,
        transport: Transport::Tcp,
    }
}

#[tokio::test]
async fn message_carrier_preserves_real_mtls_open_payload_and_half_close() {
    let f = fixture();
    let server = Server::load(&f.server).unwrap();
    // One queued frame forces progress on the peer for both handshake and data.
    let (client_io, server_io) = MessageCarrier::pair(1).unwrap();
    let mut payload = vec![0; MAX_FRAGMENT_BYTES * 3 + 509];
    rand::thread_rng().fill_bytes(&mut payload);
    let (server_shutdown, keep_receiver_alive) = tokio::sync::oneshot::channel();

    timeout(SESSION_DEADLINE, async {
        let client_session = async {
            let mut tls = f.allowed.connect(client_io).await.unwrap();
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                tls.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
            write_open(&mut tls, &open_request()).await.unwrap();
            tls.write_all(&payload).await.unwrap();
            tls.shutdown().await.unwrap();
            let mut echoed = vec![0; payload.len()];
            tls.read_exact(&mut echoed).await.unwrap();
            // Do not include private payloads in assertion failure output.
            assert!(echoed == payload, "authenticated reply payload changed");
            assert_eq!(tls.read(&mut [0; 1]).await.unwrap(), 0);
            // TLS EOF means close_notify, which can precede the underlying
            // carrier FIN. Retain the receiver until its owner finishes FIN.
            keep_receiver_alive.await.unwrap();
            drop(tls);
        };
        let server_session = async {
            let mut tls = server.accept(server_io).await.unwrap();
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3)
            );
            assert_eq!(
                tls.get_ref().1.handshake_kind(),
                Some(rustls::HandshakeKind::Full)
            );
            let peer = tls.get_ref().1.peer_certificates().unwrap();
            let fingerprint: [u8; 32] = Sha256::digest(peer[0].as_ref()).into();
            assert!(
                fingerprint == f.allowed_fingerprint,
                "unexpected authenticated peer"
            );
            let request = read_open(&mut tls).await.unwrap();
            assert!(
                request.version == 1
                    && request.host == "disposable-target.test"
                    && request.port == 443
                    && request.transport == Transport::Tcp
            );
            let mut received = vec![0; payload.len()];
            tls.read_exact(&mut received).await.unwrap();
            assert!(received == payload, "authenticated request payload changed");
            assert_eq!(tls.read(&mut [0; 1]).await.unwrap(), 0);
            // Client's TLS half-close must leave this reverse direction usable.
            tls.write_all(&received).await.unwrap();
            tls.shutdown().await.unwrap();
            server_shutdown.send(()).unwrap();
        };
        tokio::join!(client_session, server_session);
    })
    .await
    .expect("bounded message-carrier mTLS session stalled");
}

#[tokio::test]
async fn message_carrier_rejects_same_ca_wrong_device_before_application_acceptance() {
    let f = fixture();
    let server = Server::load(&f.server).unwrap();
    let (client_io, server_io) = MessageCarrier::pair(1).unwrap();
    let (client_result, server_result) = timeout(SESSION_DEADLINE, async {
        // A client TLS handshake can finish before the server checks its pin.
        // Only receipt of application data would indicate application acceptance.
        let client_session = async {
            let mut tls = f.refused.connect(client_io).await?;
            write_open(&mut tls, &open_request()).await?;
            tls.write_all(b"disposable-refused-probe").await?;
            tls.flush().await?;
            tls.read_exact(&mut [0; 1]).await.map(|_| ())
        };
        tokio::join!(client_session, server.accept(server_io))
    })
    .await
    .expect("wrong-device refusal exceeded session deadline");
    let error = server_result.err().expect("wrong device was accepted");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert!(matches!(
        AuthenticationFailure::from_io(&error),
        Some(AuthenticationFailure::DeviceNotAllowed)
    ));
    assert!(
        client_result.is_err(),
        "refused device received application data"
    );
}

#[tokio::test]
async fn message_carrier_silent_peer_uses_existing_server_handshake_timeout() {
    let mut f = fixture();
    f.server.handshake_timeout_ms = 30;
    let server = Server::load(&f.server).unwrap();
    let (silent_peer, server_io) = MessageCarrier::pair(1).unwrap();
    let error = timeout(SESSION_DEADLINE, server.accept(server_io))
        .await
        .expect("silent peer exceeded external deadline")
        .err()
        .expect("silent peer was accepted");
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(matches!(
        AuthenticationFailure::from_io(&error),
        Some(AuthenticationFailure::Timeout)
    ));
    drop(silent_peer);
}
