//! End-to-end proof of the MASQUE **direct** UDP send leg using the REAL
//! `aegis-client` product binary — no production host, no bundle token.
//!
//! Topology (all loopback):
//!
//! ```text
//!   aegis-client --masque-udp-health 127.0.0.1:<echo>
//!        │  CONNECT-UDP over QUIC/h3 (MASQUE direct, NOT via Cloudflare)
//!        ▼
//!   aegis-server (run_server: TCP+QUIC on one addr)
//!        │  real UDP socket to the target
//!        ▼
//!   UDP echo  ──────────────────────────────► datagram returned
//! ```
//!
//! This exercises the exact CONNECT-UDP carrier that the wide
//! `udp_policy = masque_direct` send bridge uses (`run_masque_udp_send` →
//! `run_masque_udp_datagram_once`): the client sends a nonce datagram, the
//! server relays it to a real UDP echo, and the echo comes back — send AND
//! receive proven at the relay. It does NOT prove the NFQUEUE divert→bridge
//! wiring on a live host, nor return-path delivery back to a local app (the
//! bridge is send-only by design — NFQUEUE is verdict-only).

mod common;

use common::{TestDir, TEST_RELAY_AUTH_TOKEN};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use std::process::Command;
use std::time::Duration;

struct OwnedTask<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Spin a local `aegis-server` (TCP + QUIC on one addr) plus a UDP echo, then
/// drive the real client binary's `--masque-udp-health` one-shot against the
/// echo through MASQUE direct CONNECT-UDP. The carrier must report healthy
/// (nonce echoed back over the relay).
#[test]
fn masque_direct_udp_send_leg_echoes_through_real_server() {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let dir = TestDir::new("udp-masque-send-e2e");
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".into()]).expect("rcgen self-signed");
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    common::write_private_file(&cert_path, cert.pem()).expect("write cert");
    common::write_private_file(&key_path, key_pair.serialize_pem()).expect("write key");

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(2)
        .build()
        .expect("server runtime");

    let server_cfg = aegis_server::config::ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: cert_path.clone(),
        key: key_path,
        auth_token: common::TEST_RELAY_AUTH_TOKEN.into(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: aegis_server::config::TargetPolicyConfig {
            profile: aegis_server::config::TargetPolicyProfile::FullVpnEgress,
            allowed_ports: Vec::new(),
        },
        transport: Default::default(),
        bundle_endpoint: Default::default(),
    };
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let mut server = OwnedTask(runtime.spawn(async move {
        aegis_server::run_server_with_bound_ready_and_shutdown(server_cfg, ready_tx, async {
            let _ = stop_rx.await;
        })
        .await
    }));
    let relay_addr = runtime.block_on(async {
        match tokio::time::timeout(Duration::from_secs(10), ready_rx).await {
            Ok(Ok(addr)) => addr.to_string(),
            Ok(Err(_)) => {
                let result = tokio::time::timeout(Duration::from_secs(3), &mut server.0).await;
                panic!("relay failed before TCP/QUIC readiness: {result:?}");
            }
            Err(error) => panic!("relay TCP/QUIC readiness deadline: {error}"),
        }
    });

    // Start the echo only after both relay sockets are owned. Independent TCP
    // and UDP port-zero reservations can choose the same number on Windows;
    // the old echo-first fixture then hid the relay's QUIC bind failure.
    // UDP echo target (the "controlled UDP target" of the live spec, loopback).
    let (echo_port, mut echo_task) = runtime.block_on(async {
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("udp echo bind");
        let port = echo.local_addr().expect("echo addr").port();
        let task = OwnedTask(tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], peer).await;
            }
        }));
        (port, task)
    });

    // Minimal client config: the --masque-udp-health one-shot only needs a
    // parseable [relay] that points at the local server (TCP addr == QUIC addr).
    let cfg_path = dir.path().join("client.toml");
    let events_path = dir.path().join("events.jsonl");
    let cfg = format!(
        r#"mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:0"

[relay]
server = "{relay_addr}"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
ca_cert = "{cert}"
masque_server = "{relay_addr}"
connect_timeout_ms = 8000
"#,
        cert = common::toml_path(&cert_path),
    );
    common::write_private_file(&cfg_path, cfg).expect("write client config");

    let bin = std::env::var_os("CARGO_BIN_EXE_aegis-client").expect("client test binary");
    let output = Command::new(bin)
        .arg("--config")
        .arg(&cfg_path)
        .arg("--diagnostic-logs")
        .arg("--runtime-events-jsonl")
        .arg(&events_path)
        .arg("--masque-udp-health")
        .arg(format!("127.0.0.1:{echo_port}"))
        .output()
        .expect("run aegis-client --masque-udp-health");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let events = std::fs::read_to_string(&events_path).unwrap_or_default();
    assert!(
        output.status.success(),
        "masque-udp-health should exit 0 (healthy carrier).\nstdout: {stdout}\nstderr: {stderr}\nevents: {events}"
    );
    assert!(
        stdout.contains("\"masque_udp_health\":true")
            || stdout.contains("\"masque_udp_health\": true"),
        "expected healthy carrier in stdout JSON.\nstdout: {stdout}\nstderr: {stderr}"
    );

    // The runtime event stream must carry the success event with the
    // no-native-fallback contract — never a native UDP path.
    assert!(
        events.contains("masque_udp_health_succeeded"),
        "expected masque_udp_health_succeeded event.\nevents:\n{events}"
    );
    assert!(
        events.contains("\"no_native_fallback\":true")
            || events.contains("\"no_native_fallback\": true"),
        "health event must assert no native fallback.\nevents:\n{events}"
    );

    stop_tx.send(()).expect("owned relay shutdown");
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(5), &mut server.0)
            .await
            .expect("relay shutdown deadline")
            .expect("relay task joined")
            .expect("relay shutdown succeeded");
        echo_task.0.abort();
        let stopped = (&mut echo_task.0).await.expect_err("echo task cancelled");
        assert!(stopped.is_cancelled());
    });
}
