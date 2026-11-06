use super::*;
use aegis_core::secure_channel::{
    self, AuthenticationFailure, Client as InnerClient, ClientSettings as InnerClientSettings,
    OpenRequest, Server as InnerServer, ServerSettings as InnerServerSettings, Transport,
};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use sha2::{Digest, Sha256};
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path};

struct InnerFixture {
    _directory: tempfile::TempDir,
    server: InnerServerSettings,
    allowed: InnerClient,
    refused: InnerClient,
}
fn private(path: &Path, bytes: &[u8]) {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}
fn inner_fixture() -> InnerFixture {
    let directory = tempfile::tempdir().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = params.self_signed(&ca_key).unwrap();
    private(&directory.path().join("ca.pem"), ca.pem().as_bytes());
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
        let cert_path = directory.path().join(format!("{name}.pem"));
        let key_path = directory.path().join(format!("{name}.key"));
        private(&cert_path, cert.pem().as_bytes());
        private(&key_path, key.serialize_pem().as_bytes());
        let digest: [u8; 32] = Sha256::digest(cert.der().as_ref()).into();
        identities.push((cert_path, key_path, digest));
    }
    let client = |index: usize| {
        InnerClient::load(&InnerClientSettings {
            server_name: "inner.test".into(),
            server_ca: directory.path().join("ca.pem"),
            cert: identities[index].0.clone(),
            key: identities[index].1.clone(),
        })
        .unwrap()
    };
    InnerFixture {
        server: InnerServerSettings {
            admission: Default::default(),
            cert: identities[0].0.clone(),
            key: identities[0].1.clone(),
            client_ca: directory.path().join("ca.pem"),
            allowed_client_sha256: vec![identities[1]
                .2
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()],
            device_registry: None,
            handshake_timeout_ms: 2000,
            idle_timeout_ms: 2000,
        },
        allowed: client(1),
        refused: client(2),
        _directory: directory,
    }
}

#[tokio::test]
async fn real_device_mtls_over_https_carrier_then_real_tcp_target() {
    timeout(DEADLINE,async {
        let mut r=Running::new(Limits::default(),"<title>Site</title>".into()).await;
        let f=inner_fixture();let server=InnerServer::load(&f.server).unwrap();let carrier=r.client().await;
        let accepted=r.accepted.recv().await.unwrap();let (io,authentication)=accepted.into_parts();
        let target=TcpListener::bind("127.0.0.1:0").await.unwrap();let address=target.local_addr().unwrap();
        let target_task=tokio::spawn(async move {let (tcp,_)=target.accept().await.unwrap();let (mut read,mut write)=tcp.into_split();tokio::io::copy(&mut read,&mut write).await.unwrap();write.shutdown().await.unwrap();});
        let serving=async {
            let _permit=server.try_acquire().unwrap();
            let (mut tls,lease)=server.accept_with_lease(io).await.unwrap();
            authentication.mark_authenticated().unwrap();
            let request=secure_channel::read_open(&mut tls).await.unwrap();assert!(request.host=="127.0.0.1" && request.port==address.port() && request.transport==Transport::Tcp);
            // The only target connection in this test occurs after the real
            // existing device pin/authorization lease and typed target request.
            let mut tcp=TcpStream::connect(address).await.unwrap();tls.write_u8(0).await.unwrap();tls.flush().await.unwrap();
            tokio::select! {result=secure_channel::copy_with_idle_timeout(&mut tls,&mut tcp,server.idle_timeout())=>{result.unwrap();},_=lease.revoked()=>panic!("fixture lease unexpectedly revoked")}
        };
        let using=async {
            let mut tls=f.allowed.connect(carrier).await.unwrap();
            assert_eq!(tls.get_ref().1.protocol_version(),Some(rustls::ProtocolVersion::TLSv1_3));
            secure_channel::write_open(&mut tls,&OpenRequest{version:1,host:"127.0.0.1".into(),port:address.port(),transport:Transport::Tcp}).await.unwrap();assert_eq!(tls.read_u8().await.unwrap(),0);
            let payload:Vec<u8>=(0..41_137).map(|i|(i%239)as u8).collect();tls.write_all(&payload).await.unwrap();tls.shutdown().await.unwrap();let mut response=Vec::new();tls.read_to_end(&mut response).await.unwrap();assert!(response==payload);
        };
        tokio::join!(serving,using);target_task.await.unwrap();until_empty(&r.server).await;r.finish().await;
    }).await.unwrap();
}

#[tokio::test]
async fn correct_bridge_key_and_wrong_same_ca_device_cannot_open_target() {
    timeout(DEADLINE, async {
        let mut r = Running::new(Limits::default(), "<title>Site</title>".into()).await;
        let f = inner_fixture();
        let server = InnerServer::load(&f.server).unwrap();
        let carrier = r.client().await;
        let (io, authentication) = r.accepted.recv().await.unwrap().into_parts();
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let serving = async {
            let result = server.accept_with_lease(io).await;
            let error = result.err().expect("same-CA unpinned device admitted");
            assert!(matches!(
                AuthenticationFailure::from_io(&error),
                Some(AuthenticationFailure::DeviceNotAllowed)
            ));
            authentication.cancel();
        };
        let using = async {
            let result = async {
                let mut tls = f.refused.connect(carrier).await?;
                secure_channel::write_open(
                    &mut tls,
                    &OpenRequest {
                        version: 1,
                        host: "127.0.0.1".into(),
                        port: address.port(),
                        transport: Transport::Tcp,
                    },
                )
                .await?;
                tls.write_all(b"refused application request").await?;
                tls.flush().await?;
                tls.read_u8().await
            }
            .await;
            assert!(
                result.is_err(),
                "wrong device received application acceptance"
            );
        };
        tokio::join!(serving, using);
        assert!(
            timeout(Duration::from_millis(50), target.accept())
                .await
                .is_err(),
            "target connected without device authorization"
        );
        until_empty(&r.server).await;
        r.finish().await;
    })
    .await
    .unwrap();
}
