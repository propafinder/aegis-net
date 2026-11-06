#![cfg(unix)]

use aegis_core::{carrier_runtime::PrivacySettings, secure_channel::ServerSettings};
use aegis_server::config::ServerConfig;
use rcgen::{
    BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use std::{
    path::Path,
    process::{Child, Command},
    time::{Duration, Instant},
};

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

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn config_file(dir: &Path, cfg: &ServerConfig, refused: bool) -> std::path::PathBuf {
    let inner = cfg.transport.inner_tls.as_ref().unwrap();
    let mut privacy = cfg.transport.authenticated_shaping.clone().unwrap();
    if refused {
        privacy.liu_channel.as_mut().unwrap().distortion_microunits = 1_000_000;
    }
    let mut text = format!(
        "listen = '127.0.0.1:0'\ncert = '{}'\nkey = '{}'\nfallback = 'close'\n[limits]\nshutdown_grace_ms = 100\n[transport]\nquic_listen = '127.0.0.1:0'\n[transport.inner_tls]\ncert = '{}'\nkey = '{}'\nclient_ca = '{}'\nallowed_client_sha256 = ['{}']\nhandshake_timeout_ms = 1000\nidle_timeout_ms = 1000\n[transport.authenticated_shaping]\n",
        cfg.cert.display(), cfg.key.display(), inner.cert.display(), inner.key.display(),
        inner.client_ca.display(), "00".repeat(32),
    );
    text.push_str(&toml::to_string(&privacy).unwrap().replace(
        "[liu_channel]",
        "[transport.authenticated_shaping.liu_channel]",
    ));
    let _: ServerConfig = toml::from_str(&text).expect("binary fixture must parse as real config");
    let path = dir.join(if refused {
        "refused.toml"
    } else {
        "ready.toml"
    });
    write_private(&path, &text);
    path
}

fn launch(config: &Path, log_path: &Path, report: bool) -> OwnedChild {
    let log = std::fs::File::create(log_path).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_aegis-server"));
    command
        .arg("--config")
        .arg(config)
        .env("AEGIS_NO_BANNER", "1")
        .env("RUST_LOG", "info")
        .stdout(log.try_clone().unwrap())
        .stderr(log);
    if report {
        command.arg("--optimizer-startup-report");
    }
    OwnedChild(command.spawn().unwrap())
}

fn read_log(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

fn wait_until(child: &mut OwnedChild, log: &Path, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if read_log(log).contains(expected) {
            return;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "binary exited before expected event: {}",
            read_log(log)
        );
        assert!(
            Instant::now() < deadline,
            "binary event deadline: {}",
            read_log(log)
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn wait_exit(child: &mut OwnedChild) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            return status;
        }
        assert!(Instant::now() < deadline, "binary exit deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn assert_report(log: &str, failures: u8) {
    let lines: Vec<_> = log
        .lines()
        .filter(|line| line.starts_with("optimizer_startup "))
        .collect();
    assert_eq!(lines.len(), 1, "binary must emit exactly one aggregate");
    assert!(lines[0].starts_with(&format!(
        "optimizer_startup attempts=1 completed=1 failures={failures} "
    )));
    assert!(lines[0].ends_with(" scope=prebind_process_aggregate"));
}

#[test]
fn binary_report_opt_in_observes_ready_and_numerical_refusal() {
    let (dir, cfg) = fixture();
    let ready_config = config_file(dir.path(), &cfg, false);
    let ready_log = dir.path().join("ready.log");
    let mut ready = launch(&ready_config, &ready_log, true);
    wait_until(
        &mut ready,
        &ready_log,
        "optimizer_startup attempts=1 completed=1 failures=0",
    );
    wait_until(&mut ready, &ready_log, "server_ingress_ready");
    assert!(
        ready.0.try_wait().unwrap().is_none(),
        "ready server must remain live"
    );
    // SAFETY: this PID belongs to the live disposable child owned by this test.
    assert_eq!(
        unsafe { libc::kill(ready.0.id() as libc::pid_t, libc::SIGTERM) },
        0
    );
    assert!(
        wait_exit(&mut ready).success(),
        "ready binary must drain successfully: {}",
        read_log(&ready_log)
    );
    assert_report(&read_log(&ready_log), 0);

    let refused_config = config_file(dir.path(), &cfg, true);
    for report in [true, false] {
        let refused_log = dir.path().join(format!("refused-{report}.log"));
        let mut refused = launch(&refused_config, &refused_log, report);
        assert!(
            !wait_exit(&mut refused).success(),
            "numerical refusal must fail binary startup"
        );
        let log = read_log(&refused_log);
        assert!(
            log.contains("positive physically impossible support"),
            "wrong refusal: {log}"
        );
        assert!(
            !log.contains("server_ingress_ready"),
            "refusal must precede ingress readiness"
        );
        if report {
            assert_report(&log, 1);
        } else {
            assert!(
                !log.contains("optimizer_startup "),
                "default must suppress aggregate"
            );
        }
    }
}
