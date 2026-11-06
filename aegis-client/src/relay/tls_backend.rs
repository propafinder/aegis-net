use aegis_core::{RelaySettings, RelayTlsBackend};
use anyhow::Context;
#[cfg(test)]
use base64::Engine;
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsConnector;

#[cfg(all(feature = "chrome-like-tls", any(unix, windows)))]
mod aws_lc;

pub(crate) trait RelayTlsIo: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

impl<T> RelayTlsIo for T where T: AsyncRead + AsyncWrite + Unpin + Send + 'static {}

pub(crate) type RelayTlsStream = Box<dyn RelayTlsIo>;

/// Whether the Chrome-class ClientHello is actually in this binary.
///
/// The config default is `chrome_like_experimental`, and a build without the
/// feature degrades to rustls at connect time. So the *configured* backend is
/// not evidence of what goes on the wire, and reporting it as such is how a
/// binary shipping the distinguishable rustls ClientHello still produced
/// runtime events that read `chrome_like_experimental`.
pub(crate) const fn chrome_like_tls_compiled_in() -> bool {
    cfg!(all(feature = "chrome-like-tls", any(unix, windows)))
}

/// The backend that will really be used: the configured one, downgraded to
/// rustls when the Chrome-class backend is not compiled in. Publish this, not
/// the configured value, anywhere the claim is about the wire.
pub(crate) fn effective_tls_backend(configured: RelayTlsBackend) -> RelayTlsBackend {
    match configured {
        RelayTlsBackend::ChromeLikeExperimental if !chrome_like_tls_compiled_in() => {
            RelayTlsBackend::Rustls
        }
        other => other,
    }
}

/// True when the operator asked for the Chrome-class ClientHello and this build
/// cannot deliver it. A silent downgrade of the headline anti-DPI capability
/// must be visible in the evidence, not only in a `warn!` line.
pub(crate) fn tls_backend_degraded(configured: RelayTlsBackend) -> bool {
    effective_tls_backend(configured) != configured
}

pub(crate) async fn connect_tls(
    settings: &RelaySettings,
    tcp: impl Into<aegis_core::relay_geneva::RelayProtectedTcp>,
    server_name: ServerName<'static>,
    verify_name: &str,
    alpn: Option<&[u8]>,
    enable_sni: bool,
) -> anyhow::Result<RelayTlsStream> {
    let protocols = alpn.map(|proto| vec![proto.to_vec()]).unwrap_or_default();
    connect_tls_with_alpn_protocols(
        settings,
        tcp,
        server_name,
        verify_name,
        &protocols,
        enable_sni,
    )
    .await
}

/// Like [`connect_tls_with_alpn_protocols`], but also reports which ALPN the
/// relay selected.
///
/// The https_ws transport needs this to implement RFC 8441: it offers Chrome's
/// `h2,http/1.1` and then speaks whichever the relay chose — extended CONNECT
/// over h2, or the HTTP/1.1 Upgrade against an older relay.
pub(crate) async fn connect_tls_with_negotiated_alpn(
    settings: &RelaySettings,
    tcp: impl Into<aegis_core::relay_geneva::RelayProtectedTcp>,
    server_name: ServerName<'static>,
    verify_name: &str,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
) -> anyhow::Result<(RelayTlsStream, Option<Vec<u8>>)> {
    connect_tls_with_negotiated_alpn_inner(
        settings,
        tcp,
        server_name,
        verify_name,
        alpn_protocols,
        enable_sni,
        #[cfg(test)]
        None,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn connect_tls_with_wire_witness(
    settings: &RelaySettings,
    tcp: impl Into<aegis_core::relay_geneva::RelayProtectedTcp>,
    server_name: ServerName<'static>,
    verify_name: &str,
    alpn: Option<&[u8]>,
    enable_sni: bool,
    wire: &aegis_server::phase_witness::IoWitness,
) -> anyhow::Result<RelayTlsStream> {
    let protocols = alpn.map(|p| vec![p.to_vec()]).unwrap_or_default();
    connect_tls_with_negotiated_alpn_inner(
        settings,
        tcp,
        server_name,
        verify_name,
        &protocols,
        enable_sni,
        Some(wire),
    )
    .await
    .map(|(stream, _alpn)| stream)
}

async fn connect_tls_with_negotiated_alpn_inner(
    settings: &RelaySettings,
    tcp: impl Into<aegis_core::relay_geneva::RelayProtectedTcp>,
    server_name: ServerName<'static>,
    verify_name: &str,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
    #[cfg(test)] wire: Option<&aegis_server::phase_witness::IoWitness>,
) -> anyhow::Result<(RelayTlsStream, Option<Vec<u8>>)> {
    let tcp = tcp.into();
    anyhow::ensure!(
        settings.outer_geneva.is_none() || tcp.is_protected(),
        "selected relay Geneva socket lacks its owned worker guard"
    );
    tcp.check_worker()?;
    anyhow::ensure!(
        settings.inner_tls.is_none(),
        "legacy TLS carrier is disabled when inner TLS is required"
    );
    match settings.tls_backend {
        RelayTlsBackend::Rustls => {
            let connector =
                rustls_tls_connector_for_settings(settings, alpn_protocols, enable_sni)?;
            #[cfg(windows)]
            let tcp = super::tls_read_fairness::WindowsRustlsTcp::new(tcp);
            #[cfg(test)]
            if let Some(wire) = wire {
                let tls = connector.connect(server_name, wire.observe(tcp)).await?;
                require_accepted_ech(settings, tls.get_ref().1.ech_status())?;
                let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                return Ok((Box::new(tls), alpn));
            }
            let tls = connector.connect(server_name, tcp).await?;
            require_accepted_ech(settings, tls.get_ref().1.ech_status())?;
            let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
            Ok((Box::new(tls), alpn))
        }
        RelayTlsBackend::ChromeLikeExperimental => {
            #[cfg(all(feature = "chrome-like-tls", any(unix, windows)))]
            {
                aws_lc::connect_aws_lc_tls_with_alpn_protocols(
                    settings,
                    tcp.into_unprotected()?,
                    verify_name,
                    alpn_protocols,
                    enable_sni,
                )
                .await
            }
            #[cfg(not(all(feature = "chrome-like-tls", any(unix, windows))))]
            {
                let _ = verify_name;
                // Required ECH keeps its configured backend; without it, the
                // profile fails here rather than on the rustls ClientHello.
                anyhow::ensure!(
                    settings.ech_config_list.is_none() && settings.ech_config_list_base64.is_none(),
                    "required ECH with tls_backend=chrome_like_experimental needs the \
                     chrome-like-tls feature; set tls_backend=rustls to use rustls"
                );
                warn_chrome_like_not_compiled_in();
                let connector =
                    rustls_tls_connector_for_settings(settings, alpn_protocols, enable_sni)?;
                #[cfg(windows)]
                let tcp = super::tls_read_fairness::WindowsRustlsTcp::new(tcp);
                #[cfg(test)]
                if let Some(wire) = wire {
                    let tls = connector.connect(server_name, wire.observe(tcp)).await?;
                    let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                    return Ok((Box::new(tls), alpn));
                }
                let tls = connector.connect(server_name, tcp).await?;
                let alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());
                Ok((Box::new(tls), alpn))
            }
        }
    }
}

#[cfg(test)]
use aegis_client::ech_policy::inline_ech_config;
#[cfg(test)]
use aegis_client::ech_policy::pinned_ech_mode;
pub(crate) use aegis_client::ech_policy::require_accepted_ech;

#[cfg(test)]
pub(crate) fn inline_ech_fixture() -> String {
    // Synthetic X25519 public basepoint, HKDF-SHA256/AES-128-GCM, cover.example.
    // Structural validation only: no private key, server or network fixture.
    let mut contents = vec![1, 0, 32, 0, 32, 9];
    contents.extend([0; 31]);
    contents.extend([0, 4, 0, 1, 0, 1, 0, 13]);
    contents.extend(b"cover.example");
    contents.extend([0, 0]);
    let mut config = vec![0xfe, 0x0d];
    config.extend((contents.len() as u16).to_be_bytes());
    config.extend(contents);
    let mut list = (config.len() as u16).to_be_bytes().to_vec();
    list.extend(config);
    base64::engine::general_purpose::STANDARD.encode(list)
}

pub(crate) fn rustls_tls_connector_for_settings(
    settings: &RelaySettings,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
) -> anyhow::Result<TlsConnector> {
    rustls_tls_connector_for_settings_with_policy(settings, alpn_protocols, enable_sni, false)
}

pub(crate) fn rustls_tls_connector_for_settings_with_policy(
    settings: &RelaySettings,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
    tls13_only_no_resumption: bool,
) -> anyhow::Result<TlsConnector> {
    let roots = load_roots(settings.ca_cert.as_deref())?;
    rustls_tls_connector_for_settings_with_roots(
        settings,
        alpn_protocols,
        enable_sni,
        tls13_only_no_resumption,
        roots,
    )
}

pub(crate) fn rustls_tls_connector_for_settings_with_explicit_roots(
    settings: &RelaySettings,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
    tls13_only_no_resumption: bool,
    roots: RootCertStore,
) -> anyhow::Result<TlsConnector> {
    rustls_tls_connector_for_settings_with_roots(
        settings,
        alpn_protocols,
        enable_sni,
        tls13_only_no_resumption,
        roots,
    )
}

fn rustls_tls_connector_for_settings_with_roots(
    settings: &RelaySettings,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
    tls13_only_no_resumption: bool,
    roots: RootCertStore,
) -> anyhow::Result<TlsConnector> {
    let cfg = rustls_client_config_for_settings_with_roots(
        settings,
        alpn_protocols,
        enable_sni,
        tls13_only_no_resumption,
        roots,
    )?;
    Ok(TlsConnector::from(Arc::new(cfg)))
}

/// The same pinned ECH and certificate policy is used by TCP and QUIC.
pub(super) fn rustls_client_config_for_settings_with_roots(
    settings: &RelaySettings,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
    tls13_only_no_resumption: bool,
    roots: RootCertStore,
) -> anyhow::Result<ClientConfig> {
    aegis_client::prepared_outer_tls::client_config_with_roots(
        settings,
        alpn_protocols,
        enable_sni,
        tls13_only_no_resumption,
        roots,
    )
}

pub(crate) async fn connect_tls_with_alpn_protocols(
    settings: &RelaySettings,
    tcp: impl Into<aegis_core::relay_geneva::RelayProtectedTcp>,
    server_name: ServerName<'static>,
    verify_name: &str,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
) -> anyhow::Result<RelayTlsStream> {
    connect_tls_with_negotiated_alpn(
        settings,
        tcp,
        server_name,
        verify_name,
        alpn_protocols,
        enable_sni,
    )
    .await
    .map(|(stream, _alpn)| stream)
}

#[cfg(not(all(feature = "chrome-like-tls", any(unix, windows))))]
fn warn_chrome_like_not_compiled_in() {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        tracing::error!(
            "relay tls backend chrome_like_experimental is NOT compiled into this \
                         binary (needs the chrome-like-tls feature on a supported target); every \
                         relay TLS connection falls back to the rustls ClientHello, which is \
                         trivially distinguishable from a browser. Rebuild with \
                         --features chrome-like-tls or set relay.tls_backend = \"rustls\" to \
                         make the downgrade explicit."
        );
    });
}

pub(crate) fn load_roots(ca_cert: Option<&Path>) -> anyhow::Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        roots.add(cert).ok();
    }
    if let Some(ca) = ca_cert {
        let f = std::fs::File::open(ca).context("open ca_cert")?;
        let mut r = std::io::BufReader::new(f);
        let certs = CertificateDer::pem_reader_iter(&mut r)
            .collect::<Result<Vec<_>, _>>()
            .context("parse ca pem")?;
        for c in certs {
            roots.add(c).ok();
        }
    }
    Ok(roots)
}

#[cfg(test)]
pub(crate) fn rustls_tls_connector(
    ca_cert: Option<&Path>,
    alpn: Option<&[u8]>,
    enable_sni: bool,
) -> anyhow::Result<TlsConnector> {
    let protocols = alpn.map(|proto| vec![proto.to_vec()]).unwrap_or_default();
    rustls_tls_connector_with_alpn_protocols(ca_cert, &protocols, enable_sni)
}

#[cfg(test)]
pub(crate) fn rustls_tls_connector_with_alpn_protocols(
    ca_cert: Option<&Path>,
    alpn_protocols: &[Vec<u8>],
    enable_sni: bool,
) -> anyhow::Result<TlsConnector> {
    let roots = load_roots(ca_cert)?;
    let mut cfg = ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.enable_sni = enable_sni;
    // An inherited debugging environment must never export traffic secrets.
    // Production builds do not provide a key-log capability.
    cfg.key_log = std::sync::Arc::new(rustls::NoKeyLog);
    if !alpn_protocols.is_empty() {
        cfg.alpn_protocols = alpn_protocols.to_vec();
    }
    Ok(TlsConnector::from(Arc::new(cfg)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::RelayTlsBackend;

    #[test]
    fn inline_ech_validates_supported_bytes_and_never_accepts_grease_or_fallback() {
        let settings = RelaySettings {
            ech_config_list_base64: Some(inline_ech_fixture()),
            tls_backend: RelayTlsBackend::Rustls,
            ..RelaySettings::default()
        };
        assert!(pinned_ech_mode(&settings).unwrap().is_some());
        for status in [
            rustls::client::EchStatus::NotOffered,
            rustls::client::EchStatus::Grease,
            rustls::client::EchStatus::Offered,
            rustls::client::EchStatus::Rejected,
        ] {
            assert!(require_accepted_ech(&settings, status).is_err());
        }
        require_accepted_ech(&settings, rustls::client::EchStatus::Accepted).unwrap();
        let both = RelaySettings {
            ech_config_list: Some("never-read.bin".into()),
            ..settings
        };
        assert!(pinned_ech_mode(&both).is_err());
    }

    #[test]
    fn inline_ech_invalid_inputs_fail_without_echoing_public_config_or_payload() {
        for value in [
            String::new(),
            "private-sentinel/not base64!".into(),
            "A".repeat(21849),
            base64::engine::general_purpose::STANDARD.encode(b"malformed-list"),
        ] {
            let error = match inline_ech_config(&value) {
                Ok(_) => panic!("invalid inline ECH config accepted"),
                Err(error) => error,
            };
            assert!(!error.to_string().contains("private-sentinel"));
            assert!(!error.to_string().contains("malformed-list"));
        }
    }

    #[test]
    fn required_ech_rejects_every_nonaccepted_handshake_status() {
        let settings = RelaySettings {
            ech_config_list: Some("pinned-ech-config.bin".into()),
            tls_backend: RelayTlsBackend::Rustls,
            ..RelaySettings::default()
        };
        for status in [
            rustls::client::EchStatus::NotOffered,
            rustls::client::EchStatus::Grease,
            rustls::client::EchStatus::Offered,
            rustls::client::EchStatus::Rejected,
        ] {
            assert!(require_accepted_ech(&settings, status).is_err());
        }
        require_accepted_ech(&settings, rustls::client::EchStatus::Accepted)
            .expect("accepted ECH is the only permitted status");
    }

    #[test]
    fn malformed_pinned_ech_config_fails_before_network_io() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ech.bin");
        std::fs::write(&path, b"not-an-ech-config-list").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let settings = RelaySettings {
            ech_config_list: Some(path),
            tls_backend: RelayTlsBackend::Rustls,
            ..RelaySettings::default()
        };
        let error = match rustls_tls_connector_for_settings(&settings, &[b"h2".to_vec()], true) {
            Ok(_) => panic!("invalid ECHConfigList must fail closed"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("validate pinned ECHConfigList"));
    }

    #[test]
    fn tls_keylog_environment_cannot_create_or_append_files() {
        // Each child receives its own inherited environment. Never mutate the
        // global process environment while other TLS tests may be running.
        let mut cases = vec![
            "relay::tls_backend::tests::rustls_backend_completes_local_tls_roundtrip_without_key_logging",
        ];
        if chrome_like_tls_compiled_in() {
            cases.push(
                "relay::tls_backend::aws_lc::tests::aws_lc_backend_completes_local_tls_roundtrip",
            );
        }
        let directory = tempfile::tempdir().unwrap();
        for (index, case) in cases.iter().enumerate() {
            for existing in [false, true] {
                let path = directory.path().join(format!("{index}-{existing}.keys"));
                if existing {
                    std::fs::write(&path, b"synthetic-existing-sentinel\n").unwrap();
                }
                let result = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", case, "--test-threads=1"])
                    .env("SSLKEYLOGFILE", &path)
                    .output()
                    .unwrap();
                assert!(
                    result.status.success(),
                    "TLS child failed: {}",
                    String::from_utf8_lossy(&result.stderr)
                );
                assert!(
                    String::from_utf8_lossy(&result.stdout).contains("1 passed"),
                    "TLS child did not run"
                );
                if existing {
                    assert!(
                        std::fs::read(&path).unwrap() == b"synthetic-existing-sentinel\n",
                        "TLS appended to an inherited key log"
                    );
                } else {
                    assert!(!path.exists(), "TLS created an inherited key log");
                }
            }
        }
    }

    #[tokio::test]
    async fn rustls_backend_completes_local_tls_roundtrip_without_key_logging() {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("ca.pem");
        std::fs::write(&cert_path, cert.cert.pem()).unwrap();
        let server_cfg = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der())),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut bytes = [0; 4];
            tls.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes, b"ping");
            tls.write_all(b"pong").await.unwrap();
        });
        // Exercise the production connector. The parent test process can set
        // SSLKEYLOGFILE without mutating process-global environment in tests.
        let connector = rustls_tls_connector(Some(&cert_path), None, true).unwrap();
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = connector
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        tls.write_all(b"ping").await.unwrap();
        let mut bytes = [0; 4];
        tls.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"pong");
        server.await.unwrap();
    }

    #[test]
    fn default_backend_is_chrome_like() {
        // Default flipped to the chrome-like (AWS-LC) backend now that JA4 parity
        // vs live Chrome is proven; rustls stays an explicit opt-out and the
        // feature-less-build fallback. browser_identical_claimed stays a measured
        // claim (false) until a wire artifact promotes it.
        let settings = RelaySettings::default();
        assert_eq!(
            settings.tls_backend,
            RelayTlsBackend::ChromeLikeExperimental
        );
        assert_eq!(settings.tls_backend.as_str(), "chrome_like_experimental");
    }

    // The configured backend is not evidence of the wire shape: without the
    // feature the connect path falls back to rustls. Reporting the configured
    // value as the backend is what let a binary with the Chrome ClientHello
    // compiled out still emit runtime events reading chrome_like_experimental.
    #[test]
    fn effective_backend_tracks_what_is_compiled_in() {
        let configured = RelayTlsBackend::ChromeLikeExperimental;
        if chrome_like_tls_compiled_in() {
            assert_eq!(effective_tls_backend(configured), configured);
            assert!(!tls_backend_degraded(configured));
        } else {
            assert_eq!(effective_tls_backend(configured), RelayTlsBackend::Rustls);
            assert!(
                tls_backend_degraded(configured),
                "a build without chrome-like-tls must report the downgrade"
            );
        }
    }

    #[test]
    fn explicit_rustls_is_never_reported_as_degraded() {
        // The operator asked for rustls and got rustls. Only an unmet
        // chrome_like_experimental request is a capability loss.
        assert_eq!(
            effective_tls_backend(RelayTlsBackend::Rustls),
            RelayTlsBackend::Rustls
        );
        assert!(!tls_backend_degraded(RelayTlsBackend::Rustls));
    }

    #[test]
    fn chrome_like_backend_is_guarded_until_proven() {
        let backend = RelayTlsBackend::ChromeLikeExperimental;
        assert_eq!(backend.as_str(), "chrome_like_experimental");
        assert!(!backend.browser_identical_claimed());
    }

    /// Config validation now admits ECH with the chrome-like backend. A build
    /// without that backend must refuse the profile before any byte is sent,
    /// not carry the required ECH list on the rustls ClientHello instead.
    #[cfg(not(all(feature = "chrome-like-tls", any(unix, windows))))]
    #[tokio::test]
    async fn required_ech_chrome_like_without_the_backend_sends_nothing() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;
        use tokio::net::{TcpListener, TcpStream};

        let _ = rustls::crypto::ring::default_provider().install_default();
        let settings = RelaySettings {
            server_name: "relay.example".into(),
            ech_config_list_base64: Some(inline_ech_fixture()),
            tls_backend: RelayTlsBackend::ChromeLikeExperimental,
            ..RelaySettings::default()
        };
        tokio::time::timeout(Duration::from_secs(10), async {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let capture = async {
                let (mut tcp, _) = listener.accept().await.unwrap();
                let mut first = vec![0; 16 * 1024];
                let n = match tokio::time::timeout(Duration::from_secs(2), tcp.read(&mut first))
                    .await
                {
                    Ok(Ok(n)) => n,
                    _ => 0,
                };
                first.truncate(n);
                first
            };
            let client = async {
                let tcp = TcpStream::connect(address).await.unwrap();
                connect_tls(
                    &settings,
                    tcp,
                    ServerName::try_from("relay.example").unwrap(),
                    "relay.example",
                    Some(b"h2"),
                    true,
                )
                .await
            };
            let (first, result) = tokio::join!(capture, client);
            assert!(result.is_err());
            assert!(
                first.is_empty(),
                "{} bytes of a rustls ClientHello reached the wire",
                first.len()
            );
        })
        .await
        .expect("refusal deadline");
    }
}

#[cfg(test)]
#[path = "tls_underlying_tests.rs"]
mod tls_underlying_tests;
