use aegis_core::{carrier_runtime::PrivacySettings, secure_channel::ServerSettings};
use aegis_server::{config::ServerConfig, phase_witness::ServerPhaseWitness};
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::{path::Path, time::Duration};
use tokio::{net::TcpStream, sync::oneshot, task::JoinHandle, time::timeout};

struct AbortOnDrop<T>(JoinHandle<T>);

impl<T> Drop for AbortOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn abort_and_join<T>(server: &mut AbortOnDrop<T>) {
    server.0.abort();
    let _ = timeout(Duration::from_secs(3), &mut server.0)
        .await
        .expect("aborted server task must join within cleanup deadline");
}

fn profile() -> PrivacySettings {
    serde_json::from_value(serde_json::json!({
        "payload_bytes":2,"cadence_ms":1,"buffer_bytes":1024,"max_wire_bytes":100000,
        "io_timeout_ms":300,"session_timeout_ms":3000,"max_queue_delay_ms":400000,
        "liu_channel":{"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],
        "server_to_client_counts":[[3,1],[1,3]],"target_classes":[],"unmatched_traffic_class":0,
        "policy_ack_class":1,"distortion_microunits":125000,"optimizer_iterations":2000,
        "optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,"buffer_bytes":1024,
        "wire_batch_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":300,
        "session_timeout_ms":3000,"max_queue_delay_ms":400000}
    }))
    .unwrap()
}

fn write_private(path: &Path, contents: &str) {
    aegis_core::secret_file::write_private_new(path, contents.as_bytes()).unwrap();
}

fn fixture() -> (tempfile::TempDir, ServerConfig) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let ca_path = dir.path().join("ca.pem");
    write_private(&ca_path, &ca.pem());
    let mut params = CertificateParams::new(vec!["inner.test".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let inner_key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let inner_cert = params.signed_by(&inner_key, &ca, &ca_key).unwrap();
    let inner_cert_path = dir.path().join("inner.pem");
    let inner_key_path = dir.path().join("inner.key");
    write_private(&inner_cert_path, &inner_cert.pem());
    write_private(&inner_key_path, &inner_key.serialize_pem());
    let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let outer_cert_path = dir.path().join("outer.pem");
    let outer_key_path = dir.path().join("outer.key");
    write_private(&outer_cert_path, &outer.cert.pem());
    write_private(&outer_key_path, &outer.key_pair.serialize_pem());
    let mut cfg = ServerConfig {
        listen: "127.0.0.1:0".into(),
        cert: outer_cert_path,
        key: outer_key_path,
        auth_token: String::new(),
        legacy_auth_tokens: Vec::new(),
        process_alias: None,
        logging: Default::default(),
        fallback: "close".into(),
        limits: Default::default(),
        rate_limit: Default::default(),
        target_policy: Default::default(),
        transport: Default::default(),
        bundle_endpoint: Default::default(),
    };
    cfg.limits.shutdown_grace_ms = 1000;
    cfg.transport.quic_listen = Some("127.0.0.1:0".into());
    cfg.transport.inner_tls = Some(ServerSettings {
        cert: inner_cert_path,
        key: inner_key_path,
        client_ca: ca_path,
        allowed_client_sha256: vec!["00".repeat(32)],
        device_registry: None,
        admission: Default::default(),
        handshake_timeout_ms: 1000,
        idle_timeout_ms: 1000,
    });
    cfg.transport.authenticated_shaping = Some(profile());
    (dir, cfg)
}

#[tokio::test]
async fn observed_optimizer_preparation_reaches_readiness_and_refusal_precedes_bind() {
    let (_dir, cfg) = fixture();
    let witness = ServerPhaseWitness::default();
    let (ready_tx, ready_rx) = oneshot::channel();
    let (stop_tx, stop_rx) = oneshot::channel();
    let mut server = AbortOnDrop(tokio::spawn(
        aegis_server::run_server_with_bound_ready_shutdown_and_witness(
            cfg.clone(),
            ready_tx,
            async {
                let _ = stop_rx.await;
            },
            witness.clone(),
        ),
    ));
    let startup: Result<(), String> = async {
        let address = timeout(Duration::from_secs(10), ready_rx)
            .await
            .map_err(|_| "readiness deadline expired".to_owned())?
            .map_err(|_| "readiness sender closed".to_owned())?;
        if address.port() == 0 {
            return Err("readiness reported an unbound port".into());
        }
        let _connection = timeout(Duration::from_secs(3), TcpStream::connect(address))
            .await
            .map_err(|_| "ready TCP connection deadline expired".to_owned())?
            .map_err(|_| "ready TCP address refused a connection".to_owned())?;
        let ready = witness.optimizer_startup_snapshot();
        if (ready.attempts, ready.completed, ready.failures) != (1, 1, 0) {
            return Err("unexpected optimizer startup aggregate at readiness".into());
        }
        Ok(())
    }
    .await;
    if let Err(reason) = startup {
        abort_and_join(&mut server).await;
        panic!("instrumented startup failed: {reason}");
    }
    let stop_sent = stop_tx.send(()).is_ok();
    let stopped = timeout(Duration::from_secs(3), &mut server.0).await;
    let result = match stopped {
        Ok(result) => result,
        Err(_) => {
            abort_and_join(&mut server).await;
            panic!("server shutdown deadline expired");
        }
    };
    assert!(stop_sent, "server exited before owned shutdown request");
    result.expect("join server task").expect("server shutdown");

    let mut refused_cfg = cfg;
    refused_cfg
        .transport
        .authenticated_shaping
        .as_mut()
        .unwrap()
        .liu_channel
        .as_mut()
        .unwrap()
        .distortion_microunits = 1_000_000;
    let refused_witness = ServerPhaseWitness::default();
    let (refused_tx, refused_rx) = oneshot::channel();
    let result = timeout(
        Duration::from_secs(10),
        aegis_server::run_server_with_bound_ready_shutdown_and_witness(
            refused_cfg,
            refused_tx,
            std::future::pending(),
            refused_witness.clone(),
        ),
    )
    .await
    .unwrap();
    let error = result.expect_err("numerical refusal must block startup");
    assert!(
        error
            .to_string()
            .contains("positive physically impossible support"),
        "startup must reach Liu's numerical causal-support refusal"
    );
    assert!(
        refused_rx.await.is_err(),
        "numerical refusal must precede readiness"
    );
    let refused = refused_witness.optimizer_startup_snapshot();
    assert_eq!(
        (refused.attempts, refused.completed, refused.failures),
        (1, 1, 1)
    );
}
