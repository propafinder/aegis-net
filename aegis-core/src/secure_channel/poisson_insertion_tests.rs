use super::*;
use crate::secure_channel::*;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
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

fn profile() -> InsertionProfile {
    InsertionProfile {
        capacity: 64,
        horizon_ms: 150,
        insertion_rate_milli: 200_000,
        overt_rate_milli: 100_000,
        max_records: 128,
        max_wire_bytes: 128 * 83,
        io_timeout_ms: 500,
        max_lateness_ms: 100,
    }
}
// Test-only midpoint draws give 3.44 ms slots at 200/s. The production
// entry point above still uses OsRng; the TLS/FIFO/count path is identical.
struct FixedMidpointRng;
impl rand::RngCore for FixedMidpointRng {
    fn next_u32(&mut self) -> u32 {
        0x8080_8080
    }
    fn next_u64(&mut self) -> u64 {
        0x8080_8080_8080_8080
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        dest.fill(0x80);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand::CryptoRng for FixedMidpointRng {}

#[tokio::test]
async fn actual_authorized_tls_owned_application_fifo_control_and_counts() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tokio::io::duplex(256);
    let app = vec![18u8; 199];
    let source = app.clone();
    let end = Instant::now() + Duration::from_secs(3);
    let mut rng = FixedMidpointRng;
    let (s, r) = tokio::join!(
        send_owned_with_rng(
            &client,
            a,
            crate::traffic_privacy::poisson_insertion::OwnedApplicationInput::new(
                Zeroizing::new(source),
                4096
            )
            .unwrap(),
            profile(),
            Zeroizing::new(b"SDK actual control".to_vec()),
            end,
            &mut rng,
        ),
        receive_owned(&server, b, Vec::new(), profile(), end)
    );
    assert!(
        s.is_ok() && r.is_ok(),
        "insertion exchange sender={:?} receiver={:?}",
        s.as_ref().err().map(|error| error.kind()),
        r.as_ref().err().map(|error| error.kind())
    );
    let sent = s.unwrap();
    let (sink, received) = r.unwrap();
    assert_eq!(sink, app);
    assert_eq!(received.control(), b"SDK actual control");
    assert!(sent.inserted_records > 0);
    assert_eq!(sent.original_bytes, 199);
    assert_eq!(sent.wire_records, received.receipt.wire_records);
}
#[tokio::test]
async fn actual_authorized_tls_wrong_profile_refuses_without_app_forwarding() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let server = Server::load(&f.server).unwrap();
    let (a, b) = tokio::io::duplex(256);
    let end = Instant::now() + Duration::from_secs(2);
    let mut other = profile();
    other.horizon_ms += 1;
    let (s, r) = tokio::join!(
        send_owned(
            &client,
            a,
            b"not sent".as_slice(),
            profile(),
            Zeroizing::new(vec![7]),
            end
        ),
        receive_owned(&server, b, Vec::new(), other, end)
    );
    assert!(s.is_err());
    assert!(r.is_err());
}
#[tokio::test]
async fn actual_tls_unauthorized_device_refuses_before_source() {
    let f = fixture();
    let client = Client::load(&f.client).unwrap();
    let mut config = f.server.clone();
    config.allowed_client_sha256 = vec!["00".repeat(32)];
    let server = Server::load(&config).unwrap();
    let (a, b) = tokio::io::duplex(256);
    let end = Instant::now() + Duration::from_secs(2);
    let (s, r) = tokio::join!(
        send_owned(
            &client,
            a,
            b"not sent".as_slice(),
            profile(),
            Zeroizing::new(vec![7]),
            end
        ),
        receive_owned(&server, b, Vec::new(), profile(), end)
    );
    assert!(s.is_err());
    assert!(r.is_err());
}
