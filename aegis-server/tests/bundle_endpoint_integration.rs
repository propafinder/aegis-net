//! End-to-end integration test for v0.2.0 S3 `/bundle` endpoint.
//!
//! Spins up a local `aegis-server` с self-signed cert on loopback,
//! issues a token via the store API directly (skipping the CLI
//! process fork to keep the test hermetic), then sends a TLS GET
//! request к the server and verifies the tarball comes back intact.
//! Also verifies the one-time semantics (second request с same token
//! → 410 Gone).

use aegis_server::bundle_tokens::BundleTokenStore;
use aegis_server::config::{BundleEndpointConfig, ServerConfig};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

fn private_store_fixture_dir() -> TempDir {
    // The store refuses symlinked ancestors, including macOS's /var alias.
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    TempDir::new_in(workspace).expect("private store fixture")
}

fn write_self_signed(dir: &std::path::Path) -> (PathBuf, PathBuf, Vec<u8>) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen");
    let cert_path = dir.join("server.pem");
    let key_path = dir.join("server-key.pem");
    fs::write(&cert_path, cert.pem()).expect("write cert");
    fs::write(&key_path, key_pair.serialize_pem()).expect("write key");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let der = cert.der().as_ref().to_vec();
    (cert_path, key_path, der)
}

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = l.local_addr().expect("addr").port();
    drop(l);
    port
}

async fn tls_get_bundle(port: u16, cert_der: &[u8], path_with_query: &str) -> (u16, Vec<u8>) {
    let (code, body, _) =
        tls_get_bundle_with_alpn(port, cert_der, path_with_query, Vec::new()).await;
    (code, body)
}

async fn tls_get_bundle_with_alpn(
    port: u16,
    cert_der: &[u8],
    path_with_query: &str,
    alpn_protocols: Vec<Vec<u8>>,
) -> (u16, Vec<u8>, Option<Vec<u8>>) {
    let mut root = RootCertStore::empty();
    root.add(CertificateDer::from(cert_der.to_vec()))
        .expect("add root");
    let mut config = ClientConfig::builder()
        .with_root_certificates(root)
        .with_no_client_auth();
    config.alpn_protocols = alpn_protocols;
    let config = Arc::new(config);
    let connector = TlsConnector::from(config);
    let stream = TcpStream::connect(("127.0.0.1", port)).await.expect("tcp");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector.connect(server_name, stream).await.expect("tls");
    let selected_alpn = tls.get_ref().1.alpn_protocol().map(|proto| proto.to_vec());

    let req =
        format!("GET {path_with_query} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
    tls.write_all(req.as_bytes()).await.expect("write req");
    tls.flush().await.expect("flush");

    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf)).await;

    if buf.is_empty() {
        // Server closed без writing anything — treat as "no response"
        // which surfaces as code=0 (sentinel). Callers expecting a real
        // HTTP response should fail the assertion; callers checking the
        // disabled-endpoint case just need "not 200".
        return (0, Vec::new(), selected_alpn);
    }
    let Some(headers_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        eprintln!(
            "bundle_endpoint test: unexpected non-HTTP response ({} bytes): {:?}",
            buf.len(),
            String::from_utf8_lossy(&buf[..buf.len().min(120)])
        );
        return (0, buf, selected_alpn);
    };
    let header_str = std::str::from_utf8(&buf[..headers_end]).expect("utf8");
    let status_line = header_str.lines().next().expect("status line");
    let parts: Vec<&str> = status_line.split_whitespace().collect();
    let code: u16 = parts[1].parse().expect("status code");
    let body = buf[headers_end + 4..].to_vec();
    (code, body, selected_alpn)
}

/// Issue a `GET path_with_query` over an HTTP/2 connection (ALPN `h2`),
/// mirroring how a Cloudflare-fronted edge fetches from the origin.
/// Returns (status_code, body_bytes, negotiated_alpn).
async fn h2_get(
    port: u16,
    cert_der: &[u8],
    path_with_query: &str,
) -> (u16, Vec<u8>, Option<Vec<u8>>) {
    let mut root = RootCertStore::empty();
    root.add(CertificateDer::from(cert_der.to_vec()))
        .expect("add root");
    let mut config = ClientConfig::builder()
        .with_root_certificates(root)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(("127.0.0.1", port)).await.expect("tcp");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let tls = connector.connect(server_name, stream).await.expect("tls");
    let selected_alpn = tls.get_ref().1.alpn_protocol().map(|p| p.to_vec());

    let (h2, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut h2 = h2.ready().await.expect("h2 ready");

    let req = http::Request::builder()
        .method("GET")
        .uri(format!("https://localhost{path_with_query}"))
        .body(())
        .expect("build request");
    let (response, _send) = h2.send_request(req, true).expect("send_request");
    let response = response.await.expect("response");
    let code = response.status().as_u16();
    let mut body_stream = response.into_body();
    let mut body = Vec::new();
    while let Some(chunk) = body_stream.data().await {
        let chunk = chunk.expect("body chunk");
        let _ = body_stream.flow_control().release_capacity(chunk.len());
        body.extend_from_slice(&chunk);
    }
    (code, body, selected_alpn)
}

async fn spawn_server(cfg: ServerConfig) -> tokio::task::JoinHandle<()> {
    let port = cfg
        .listen
        .rsplit_once(':')
        .and_then(|(_, p)| p.parse::<u16>().ok())
        .expect("port from listen");
    let handle = tokio::spawn(async move {
        let _ = aegis_server::run_server(cfg).await;
    });
    // Poll для readiness: try connecting к the TCP port until success или
    // timeout. Avoids flake от too-short fixed sleep.
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return handle;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not become ready within 5s");
}

#[tokio::test]
async fn bundle_endpoint_serves_tarball_once() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("aegis_server=debug")
        .with_test_writer()
        .try_init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = private_store_fixture_dir();
    let (cert_path, key_path, cert_der) = write_self_signed(tmp.path());
    let bundle_path = tmp.path().join("client-bundle.tar.gz");
    let bundle_contents = b"fake-but-unique-client-bundle-payload";
    fs::write(&bundle_path, bundle_contents).expect("write bundle");
    let token_store_path = tmp.path().join("tokens.json");

    // Pre-populate token store before starting the server.
    let plaintext = {
        let mut store = BundleTokenStore::load(&token_store_path).expect("load");
        store
            .issue(bundle_path.clone(), 3600, Some("integration-test".into()))
            .expect("issue")
    };

    let port = free_port().await;
    let cfg = ServerConfig {
        listen: format!("127.0.0.1:{port}"),
        cert: cert_path,
        key: key_path,
        auth_token: "aa57a0d2751d6bd68a94705288c16aba382a6cdf06c0466530732eba968d3029".into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: BundleEndpointConfig {
            enabled: true,
            token_store_path: token_store_path.clone(),
            default_token_ttl_secs: 3600,
            path_prefix: "/bundle".into(),
        },
    };

    let _server = spawn_server(cfg).await;

    // First request — should succeed with 200 + body == bundle_contents.
    let (code, body) = tls_get_bundle(port, &cert_der, &format!("/bundle?token={plaintext}")).await;
    assert_eq!(code, 200, "first redemption should be 200 OK");
    assert_eq!(
        body.as_slice(),
        bundle_contents,
        "body should equal bundle tarball bytes"
    );

    // Second request — token is consumed (one-time). Active-probing
    // hardening: the WIRE response is a generic web decoy, NOT a 410 "Gone"
    // token tell. Assert decoy-shaped (not 200, stock web status) and that
    // it leaks no token/AEGIS string.
    let (code2, body2) =
        tls_get_bundle(port, &cert_der, &format!("/bundle?token={plaintext}")).await;
    assert_ne!(code2, 200, "consumed token must not serve tarball");
    assert!(
        matches!(code2, 301 | 403 | 404 | 410),
        "consumed token should get a generic web decoy status, got {code2}"
    );
    let body2s = String::from_utf8_lossy(&body2).to_lowercase();
    assert!(
        !body2s.contains("token") && !body2s.contains("aegis"),
        "decoy body must not leak token semantics"
    );

    // Wrong path — must NOT serve tarball. Either a 4xx HTTP response
    // или an immediate close (code=0 sentinel) is acceptable here: the
    // existing WebSocket handler closes TLS без response when the
    // upgrade protocol fails, and that is the correct behaviour for a
    // non-bundle / non-WS request. The hard invariant is "not 200".
    let (code3, body3) =
        tls_get_bundle(port, &cert_der, &format!("/not-bundle?token={plaintext}")).await;
    assert_ne!(code3, 200, "non-bundle path must not serve tarball");
    assert!(
        body3.as_slice() != bundle_contents,
        "non-bundle path must never return bundle bytes"
    );
}

#[tokio::test]
async fn bundle_endpoint_accepts_http1_when_client_requests_http1() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = private_store_fixture_dir();
    let (cert_path, key_path, cert_der) = write_self_signed(tmp.path());
    let bundle_path = tmp.path().join("client-bundle.tar.gz");
    let bundle_contents = b"mixed-alpn-client-bundle-payload";
    fs::write(&bundle_path, bundle_contents).expect("write bundle");
    let token_store_path = tmp.path().join("tokens.json");

    let plaintext = {
        let mut store = BundleTokenStore::load(&token_store_path).expect("load");
        store
            .issue(bundle_path.clone(), 3600, Some("mixed-alpn".into()))
            .expect("issue")
    };

    let port = free_port().await;
    let cfg = ServerConfig {
        listen: format!("127.0.0.1:{port}"),
        cert: cert_path,
        key: key_path,
        auth_token: "aa57a0d2751d6bd68a94705288c16aba382a6cdf06c0466530732eba968d3029".into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: BundleEndpointConfig {
            enabled: true,
            token_store_path,
            default_token_ttl_secs: 3600,
            path_prefix: "/bundle".into(),
        },
    };

    let _server = spawn_server(cfg).await;
    let offered = vec![b"http/1.1".to_vec()];
    let (code, body, selected_alpn) = tls_get_bundle_with_alpn(
        port,
        &cert_der,
        &format!("/bundle?token={plaintext}"),
        offered,
    )
    .await;
    assert_eq!(
        selected_alpn.as_deref(),
        Some(&b"http/1.1"[..]),
        "bundle bootstrap clients must request http/1.1 explicitly"
    );
    assert_eq!(code, 200, "http/1.1 bundle request should be 200 OK");
    assert_eq!(body.as_slice(), bundle_contents);

    let offered = vec![b"http/1.1".to_vec()];
    let (invalid_code, _invalid_body, invalid_alpn) =
        tls_get_bundle_with_alpn(port, &cert_der, "/bundle?token=definitely-invalid", offered)
            .await;
    assert_eq!(invalid_alpn.as_deref(), Some(&b"http/1.1"[..]));
    // Active-probing hardening: an invalid token gets a generic web decoy,
    // not a 403 token tell. Not 200, stock web status.
    assert_ne!(invalid_code, 200, "invalid token must not serve tarball");
    assert!(
        matches!(invalid_code, 301 | 403 | 404 | 410),
        "invalid token should get a generic web decoy status, got {invalid_code}"
    );
}

/// A HEAD probe (common scanner verb) must get a stock-web decoy: same
/// header shape as the GET decoy but NO body, and no AEGIS tell.
#[tokio::test]
async fn head_probe_returns_decoy_headers_no_body() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let tmp = private_store_fixture_dir();
    let (cert_path, key_path, cert_der) = write_self_signed(tmp.path());
    let port = free_port().await;
    let cfg = ServerConfig {
        listen: format!("127.0.0.1:{port}"),
        cert: cert_path,
        key: key_path,
        auth_token: "aa57a0d2751d6bd68a94705288c16aba382a6cdf06c0466530732eba968d3029".into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: BundleEndpointConfig {
            enabled: true,
            token_store_path: tmp.path().join("tokens.json"),
            default_token_ttl_secs: 3600,
            path_prefix: "/bundle".into(),
        },
    };
    let _server = spawn_server(cfg).await;

    // Raw HEAD over TLS (http/1.1 ALPN).
    let mut root = RootCertStore::empty();
    root.add(CertificateDer::from(cert_der)).expect("root");
    let mut conf = ClientConfig::builder()
        .with_root_certificates(root)
        .with_no_client_auth();
    conf.alpn_protocols = vec![b"http/1.1".to_vec()];
    let connector = TlsConnector::from(Arc::new(conf));
    let stream = TcpStream::connect(("127.0.0.1", port)).await.expect("tcp");
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .expect("tls");
    tls.write_all(b"HEAD /random-scan HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write");
    tls.flush().await.expect("flush");
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf)).await;
    let text = String::from_utf8_lossy(&buf);
    let lower = text.to_lowercase();

    assert!(text.starts_with("HTTP/1.1 "), "expected an HTTP response");
    assert!(
        lower.contains("server:"),
        "decoy must carry a Server header"
    );
    let headers_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header terminator");
    assert!(
        buf[headers_end + 4..].is_empty(),
        "HEAD response must have NO body"
    );
    assert!(
        !lower.contains("aegis") && !lower.contains("relay") && !lower.contains("tunnel"),
        "HEAD decoy must not leak an AEGIS tell"
    );
}

#[tokio::test]
async fn bundle_endpoint_disabled_returns_not_found_shape() {
    // With endpoint disabled, GET /bundle? should NOT be handled by the
    // bundle module — it falls through к the websocket handler which
    // typically rejects the request. This test just makes sure the
    // server doesn't crash or double-consume when the disabled path
    // is hit.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = private_store_fixture_dir();
    let (cert_path, key_path, cert_der) = write_self_signed(tmp.path());
    let port = free_port().await;
    let cfg = ServerConfig {
        listen: format!("127.0.0.1:{port}"),
        cert: cert_path,
        key: key_path,
        auth_token: "aa57a0d2751d6bd68a94705288c16aba382a6cdf06c0466530732eba968d3029".into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: BundleEndpointConfig {
            enabled: false,
            ..Default::default()
        },
    };

    let _server = spawn_server(cfg).await;

    // Request should not 200+tarball. Exact status depends on downstream
    // websocket handler behaviour; we only assert that we don't get 200.
    let (code, _body) = tls_get_bundle(port, &cert_der, "/bundle?token=whatever").await;
    assert_ne!(code, 200, "disabled endpoint must never serve tarball");
}

/// Regression test for the Cloudflare-fronted bundle 404: a CDN edge
/// negotiates `h2` ALPN to the origin, so `GET /bundle` arrives on the
/// HTTP/2 path. It must now be served (200 + tarball) instead of routing
/// to the gRPC handler and 404'ing. Also checks one-time semantics over
/// h2 and that an unknown h2 GET path still 404s.
#[tokio::test]
async fn bundle_endpoint_serves_tarball_over_http2() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let tmp = private_store_fixture_dir();
    let (cert_path, key_path, cert_der) = write_self_signed(tmp.path());
    let bundle_path = tmp.path().join("client-bundle.tar.gz");
    let bundle_contents = b"http2-fronted-client-bundle-payload";
    fs::write(&bundle_path, bundle_contents).expect("write bundle");
    let token_store_path = tmp.path().join("tokens.json");

    let plaintext = {
        let mut store = BundleTokenStore::load(&token_store_path).expect("load");
        store
            .issue(bundle_path.clone(), 3600, Some("h2-test".into()))
            .expect("issue")
    };

    let port = free_port().await;
    let cfg = ServerConfig {
        listen: format!("127.0.0.1:{port}"),
        cert: cert_path,
        key: key_path,
        auth_token: "aa57a0d2751d6bd68a94705288c16aba382a6cdf06c0466530732eba968d3029".into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: BundleEndpointConfig {
            enabled: true,
            token_store_path,
            default_token_ttl_secs: 3600,
            path_prefix: "/bundle".into(),
        },
    };

    let _server = spawn_server(cfg).await;

    // First redemption over h2 — must be 200 + exact tarball bytes.
    let (code, body, alpn) = h2_get(port, &cert_der, &format!("/bundle?token={plaintext}")).await;
    assert_eq!(
        alpn.as_deref(),
        Some(&b"h2"[..]),
        "test must actually negotiate h2"
    );
    assert_eq!(code, 200, "h2 GET /bundle should be 200 OK (was 404)");
    assert_eq!(
        body.as_slice(),
        bundle_contents,
        "h2 body should equal bundle tarball bytes"
    );

    // Second redemption over h2 — token consumed. Active-probing hardening:
    // generic web decoy, not a 410 token tell. Not 200; stock web status.
    let (code2, b2, _a2) = h2_get(port, &cert_der, &format!("/bundle?token={plaintext}")).await;
    assert_ne!(code2, 200, "consumed h2 token must not serve tarball");
    assert!(
        matches!(code2, 403 | 404 | 410),
        "consumed h2 token should get a generic web decoy, got {code2}"
    );
    assert!(
        !String::from_utf8_lossy(&b2)
            .to_lowercase()
            .contains("aegis"),
        "h2 decoy body must not leak AEGIS"
    );

    // Unknown h2 GET path (gRPC dispatch) → generic web decoy, not bare 404.
    let (code3, _b3, _a3) = h2_get(port, &cert_der, "/not-a-bundle?token=x").await;
    assert_ne!(code3, 200);
    assert!(
        matches!(code3, 403 | 404 | 410),
        "non-bundle h2 GET should get a generic web decoy, got {code3}"
    );

    // Invalid token over h2 → generic web decoy (not a 403 token tell).
    let (code4, _b4, _a4) = h2_get(port, &cert_der, "/bundle?token=definitely-invalid").await;
    assert_ne!(code4, 200, "invalid h2 token must not serve tarball");
    assert!(
        matches!(code4, 403 | 404 | 410),
        "invalid h2 token should get a generic web decoy, got {code4}"
    );
}
