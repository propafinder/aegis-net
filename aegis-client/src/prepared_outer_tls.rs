//! Shared outer TLS configuration for the binary relay and a future provider.
//! Preparing a connector is neither a network dial nor authenticated PolicyAck.
use aegis_core::{
    h2_stream::H2Stream,
    https_bridge::{Credential, Purpose, KEY_HEADER},
    secure_channel::{self, grpc_io::GrpcIo},
    RelaySettings, RelayTlsBackend,
};
use anyhow::{ensure, Context};
use rustls::{ClientConfig, RootCertStore};
use std::{future::Future, pin::Pin, sync::Arc, time::Duration};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The exact product TLS/ECH builder. Callers supply separately admitted roots.
/// Legacy binary callers may still use file-backed ECH through pinned_ech_mode;
/// the provider entry point below rejects that case before calling this.
pub fn client_config_with_roots(
    settings: &RelaySettings,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
    tls13_only_no_resumption: bool,
    roots: RootCertStore,
) -> anyhow::Result<ClientConfig> {
    Ok(client_config_with_roots_impl(
        settings,
        alpn_protocols,
        enable_sni,
        tls13_only_no_resumption,
        roots,
        false,
    )?
    .0)
}

fn client_config_with_roots_impl(
    settings: &RelaySettings,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
    tls13_only_no_resumption: bool,
    roots: RootCertStore,
    pinned_only: bool,
) -> anyhow::Result<(ClientConfig, Option<crate::ech_policy::RotationToken>)> {
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()));
    let (ech, rotation) = if pinned_only {
        (crate::ech_policy::original_pinned_ech_mode(settings)?, None)
    } else {
        crate::ech_policy::pinned_ech_mode_with_token(settings)?
    };
    let builder = if let Some(ech) = ech {
        ensure!(enable_sni, "required ECH cannot run with SNI disabled");
        builder.with_ech(ech).context("enable RFC 9849 ECH")?
    } else if tls13_only_no_resumption {
        builder
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("select TLS 1.3")?
    } else {
        builder
            .with_safe_default_protocol_versions()
            .context("select TLS protocol versions")?
    };
    let mut cfg = builder.with_root_certificates(roots).with_no_client_auth();
    cfg.enable_sni = enable_sni;
    cfg.key_log = Arc::new(rustls::NoKeyLog);
    if !alpn_protocols.is_empty() {
        cfg.alpn_protocols = alpn_protocols.to_vec();
    }
    if tls13_only_no_resumption {
        cfg.resumption = rustls::client::Resumption::disabled();
    }
    Ok((cfg, rotation))
}

/// Prepare the H2 outer connector from one held public CA snapshot. This
/// provider prerequisite refuses file-backed ECH rather than reopening it.
/// The caller still must verify ECH acceptance after a later handshake.
pub fn explicit_h2_connector_from_pem(
    settings: &RelaySettings,
    outer_ca_pem: &[u8],
) -> anyhow::Result<TlsConnector> {
    Ok(explicit_h2_connector_from_pem_impl(settings, outer_ca_pem, false)?.0)
}

/// Return the learned ECH generation captured by this exact connector. The
/// held pool refuses mixed generations before publishing a multi-pin pool.
pub fn explicit_h2_connector_from_pem_with_rotation(
    settings: &RelaySettings,
    outer_ca_pem: &[u8],
) -> anyhow::Result<(TlsConnector, Option<crate::ech_policy::RotationToken>)> {
    explicit_h2_connector_from_pem_impl(settings, outer_ca_pem, false)
}

/// The same held-CA and ECH-required connector, built from the signed ECH
/// list rather than a learned rotation. Only the provider's local rollback
/// generation uses this; the ordinary dial still uses cached rotations.
pub fn explicit_h2_connector_from_pem_pinned(
    settings: &RelaySettings,
    outer_ca_pem: &[u8],
) -> anyhow::Result<TlsConnector> {
    Ok(explicit_h2_connector_from_pem_impl(settings, outer_ca_pem, true)?.0)
}

fn explicit_h2_connector_from_pem_impl(
    settings: &RelaySettings,
    outer_ca_pem: &[u8],
    pinned_only: bool,
) -> anyhow::Result<(TlsConnector, Option<crate::ech_policy::RotationToken>)> {
    ensure!(settings.inner_tls.is_some(), "inner TLS identity required");
    ensure!(settings.ca_cert.is_some(), "explicit outer CA required");
    ensure!(
        settings.tls_backend == RelayTlsBackend::Rustls,
        "prepared outer H2 requires rustls"
    );
    ensure!(
        settings.ech_config_list.is_none(),
        "file-backed ECH requires held-descriptor capture"
    );
    settings
        .validate_inner_tls_transport()
        .map_err(anyhow::Error::msg)?;
    let roots = secure_channel::trust_roots_from_pem(outer_ca_pem)?;
    let (config, rotation) =
        client_config_with_roots_impl(settings, &[b"h2".to_vec()], true, true, roots, pinned_only)?;
    Ok((TlsConnector::from(Arc::new(config)), rotation))
}

/// Build the exact H2 carrier request from an already held bridge credential.
/// The caller must have captured and revalidated its source; this function
/// never reads `credential_file`. No socket or device identity is created.
pub fn h2_carrier_request_from_held(
    settings: &RelaySettings,
    credential: Option<&Credential>,
    purpose: Purpose,
) -> anyhow::Result<http::Request<()>> {
    let authority = crate::relay_endpoint_policy::relay_transport_authority(settings)?;
    let (request_authority, path) = if let Some(bridge) = &settings.https_bridge {
        bridge.validate_authority(&settings.server_name)?;
        ensure!(
            credential.is_some(),
            "held HTTPS bridge credential required"
        );
        (bridge.authority.as_str(), bridge.path(purpose))
    } else {
        ensure!(credential.is_none(), "unexpected HTTPS bridge credential");
        (
            authority.authority_host.as_str(),
            match purpose {
                Purpose::Traffic => secure_channel::GRPC_PATH,
                Purpose::Enrollment => secure_channel::enrollment_tls::GRPC_PATH,
            },
        )
    };
    let uri = format!(
        "https://{}{}",
        crate::relay_endpoint_policy::format_authority_host(request_authority),
        path
    );
    let mut request = http::Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/grpc")
        .header("te", "trailers");
    if let Some(credential) = credential {
        request = request.header(KEY_HEADER, credential.header_value());
    }
    Ok(request.body(())?)
}

/// The real H2 connection future, retained as a value rather than spawned.
/// A future composite must poll it while carrying the stream and may release
/// its Store only after the stream and this future are terminal or dropped.
pub type HeldH2Driver = Pin<Box<dyn Future<Output = Result<(), h2::Error>> + Send>>;

/// Authenticated outer H2 carrier plus its unspawned connection driver.
/// This is not device authentication or a packet permit.
#[must_use = "the H2 driver must be polled and terminally owned with the carrier"]
pub struct HeldH2Connection {
    stream: GrpcIo<H2Stream>,
    driver: HeldH2Driver,
}

impl HeldH2Connection {
    /// Transfer both values into the same future terminal session owner.
    pub fn into_parts(self) -> (GrpcIo<H2Stream>, HeldH2Driver) {
        (self.stream, self.driver)
    }
}

/// Connect one already established TCP socket through held CA bytes, verified
/// TLS/ECH and negotiated h2, then require a successful gRPC carrier response.
/// The caller owns the product TCP/Geneva dial and must have revalidated its
/// captured inputs before opening that socket. No path or secret file is read.
pub async fn connect_h2_from_held(
    settings: &RelaySettings,
    outer_ca_pem: &[u8],
    credential: Option<&Credential>,
    purpose: Purpose,
    tcp: TcpStream,
) -> anyhow::Result<HeldH2Connection> {
    ensure!(
        (1..=60_000).contains(&settings.connect_timeout_ms),
        "invalid held carrier connect timeout"
    );
    // One original budget covers TLS, H2 handshake and carrier response. The
    // H2 driver is unspawned, so timeout drops it without leaving a child.
    let deadline = tokio::time::Instant::now() + Duration::from_millis(settings.connect_timeout_ms);
    let request = h2_carrier_request_from_held(settings, credential, purpose)?;
    let connector = explicit_h2_connector_from_pem(settings, outer_ca_pem)?;
    let authority = crate::relay_endpoint_policy::relay_transport_authority(settings)?;
    tokio::time::timeout_at(deadline, async move {
        let tls = match connector.connect(authority.tls_server_name, tcp).await {
            Ok(tls) => tls,
            Err(error) => {
                // The caller owns the dial, so an authenticated ECH rotation is
                // only learned here; its next held connect uses the new config.
                let _ = crate::ech_policy::record_rejection(settings, &error);
                return Err(error.into());
            }
        };
        crate::ech_policy::require_accepted_ech(settings, tls.get_ref().1.ech_status())?;
        ensure!(
            tls.get_ref().1.alpn_protocol() == Some(b"h2"),
            "secure carrier requires HTTP/2"
        );
        let (mut client, connection) = h2::client::Builder::new().handshake(tls).await?;
        let mut driver: HeldH2Driver = Box::pin(connection);
        let (response, send) = client.send_request(request, false)?;
        let response = tokio::select! {
            response = response => response?,
            terminal = &mut driver => anyhow::bail!("H2 driver ended before carrier response: {terminal:?}"),
        };
        ensure!(
            response.status() == http::StatusCode::OK,
            "secure carrier rejected with HTTP {}",
            response.status()
        );
        ensure!(
            response
                .headers()
                .get("content-type")
                .is_some_and(|h| h == "application/grpc"),
            "invalid secure carrier content type"
        );
        Ok(HeldH2Connection {
            stream: GrpcIo::new(H2Stream::new(send, response.into_body())),
            driver,
        })
    })
    .await
    .context("held carrier connect deadline exhausted")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use aegis_core::https_bridge::{ClientSettings as BridgeSettings, Gate, ServerSettings};
    use aegis_core::{secure_channel::ClientSettings, TunnelTransportFamily};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn settings() -> RelaySettings {
        RelaySettings {
            server_name: "localhost".into(),
            ca_cert: Some("/nonexistent/outer-ca.pem".into()),
            inner_tls: Some(ClientSettings {
                server_name: "origin.test".into(),
                server_ca: "/nonexistent/inner-ca.pem".into(),
                cert: "/nonexistent/device.pem".into(),
                key: "/nonexistent/device.key".into(),
            }),
            transport_priority: vec![TunnelTransportFamily::GrpcStream],
            udp_transport_priority: Some(vec![TunnelTransportFamily::GrpcDatagram]),
            tls_backend: RelayTlsBackend::Rustls,
            ..Default::default()
        }
    }

    #[cfg(unix)]
    #[test]
    fn held_bridge_request_survives_file_removal_and_matches_live_gate() {
        use std::{io::Write, os::unix::fs::PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bridge.key");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.write_all(&[b'a'; 64]).unwrap();
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .unwrap();
        let bridge = BridgeSettings {
            authority: "bridge.test".into(),
            path: "/private/stream".into(),
            enrollment_path: "/private/enroll".into(),
            credential_file: path.clone(),
        };
        let gate = Gate::load(&ServerSettings {
            carrier: bridge.clone(),
            site_html: "<title>Fixture</title>".into(),
        })
        .unwrap();
        let held = Credential::from_captured_bytes(&[b'a'; 64]).unwrap();
        std::fs::remove_file(&path).unwrap();
        let mut relay = settings();
        relay.server_name = "bridge.test".into();
        relay.https_bridge = Some(bridge);
        assert!(relay
            .https_bridge
            .as_ref()
            .unwrap()
            .load_credential()
            .is_err());
        let traffic = h2_carrier_request_from_held(&relay, Some(&held), Purpose::Traffic).unwrap();
        assert!(gate.admits(&traffic, Purpose::Traffic));
        assert!(!gate.admits(&traffic, Purpose::Enrollment));
        assert!(traffic.headers().get(KEY_HEADER).unwrap().is_sensitive());
        let enrollment =
            h2_carrier_request_from_held(&relay, Some(&held), Purpose::Enrollment).unwrap();
        assert!(gate.admits(&enrollment, Purpose::Enrollment));
        assert!(h2_carrier_request_from_held(&relay, None, Purpose::Traffic).is_err());
        let wrong = Credential::from_captured_bytes(&[b'b'; 64]).unwrap();
        let wrong = h2_carrier_request_from_held(&relay, Some(&wrong), Purpose::Traffic).unwrap();
        assert!(!gate.admits(&wrong, Purpose::Traffic));
    }

    #[tokio::test]
    async fn prepared_connector_dials_with_held_ca_after_source_mutation() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut ca = cert.cert.pem().into_bytes();
        let connector = explicit_h2_connector_from_pem(&settings(), &ca).unwrap();
        ca.fill(0);

        let mut server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
            )
            .unwrap();
        server_cfg.alpn_protocols = vec![b"h2".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
            let mut bytes = [0; 4];
            tls.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        tls.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        tls.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn prepared_connector_refuses_file_ech_and_bad_held_ca() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let mut with_file_ech = settings();
        with_file_ech.ech_config_list = Some("/nonexistent/ech.bin".into());
        assert!(
            explicit_h2_connector_from_pem(&with_file_ech, cert.cert.pem().as_bytes()).is_err()
        );
        assert!(explicit_h2_connector_from_pem(&settings(), b"invalid certificate").is_err());
        assert!(explicit_h2_connector_from_pem(&settings(), &vec![b'X'; 1_048_577]).is_err());
    }
}
