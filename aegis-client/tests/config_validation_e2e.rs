mod common;

use common::{write_private_file, TestDir, TEST_RELAY_AUTH_TOKEN};
use std::net::TcpListener;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

// A regression must fail promptly if validation accidentally becomes client startup.
fn run_bounded(command: &mut Command) -> Output {
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let output = child.wait_with_output().unwrap();
            panic!(
                "validation did not exit: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn client() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aegis-client"))
}

#[test]
fn validation_loads_config_without_listener_state_events_or_notify() {
    let dir = TestDir::new("validation-no-runtime");
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = dir.path().join("config.toml");
    let events = dir.path().join("events.jsonl");
    let state = dir.path().join("state.json");
    write_private_file(&config, format!(
        "mode = 'relay'\n[ingress]\nprimary = 'socks5'\n[socks]\nlisten = '{}'\n[direct]\nstate_path = '{}'\n[relay]\nserver = '127.0.0.1:8443'\nauth_token = '{}'\n",
        listener.local_addr().unwrap(), state.display(), TEST_RELAY_AUTH_TOKEN
    )).unwrap();
    let output = run_bounded(
        client()
            .args(["--validate-config", "--json", "--config"])
            .arg(&config)
            .arg("--runtime-events-jsonl")
            .arg(&events)
            // Real startup would also fail on this configured, unavailable notify socket.
            .env("NOTIFY_SOCKET", dir.path().join("missing-notify")),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"schema": "aegis_config_validation_v1", "valid": true})
    );
    assert!(output.stderr.is_empty());
    assert!(!events.exists());
    assert!(!state.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn invalid_config_does_not_expose_secret_or_create_events() {
    let dir = TestDir::new("validation-private-error");
    let config = dir.path().join("bad.toml");
    let events = dir.path().join("events.jsonl");
    let secret = "synthetic-invalid-secret-do-not-print";
    write_private_file(
        &config,
        format!("mode = 'relay'\n[relay]\nserver = '127.0.0.1:8443'\nauth_token = '{secret}'\n"),
    )
    .unwrap();
    let output = run_bounded(
        client()
            .args(["--validate-config", "--json", "--config"])
            .arg(&config)
            .arg("--runtime-events-jsonl")
            .arg(&events),
    );
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("client_failed"), "{stderr}");
    assert!(!stderr.contains(secret));
    assert!(!events.exists());
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn validation_cannot_execute_a_subcommand() {
    let output = run_bounded(client().args([
        "--validate-config",
        "operator",
        "plan",
        "--mode",
        "client-socks",
    ]));
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn process_readiness_follows_successful_bind_and_is_absent_on_bind_failure() {
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::os::unix::net::UnixDatagram;

    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let dir = TestDir::new("service-process-ready");
    let config = dir.path().join("config.toml");
    let notify_path = dir.path().join("notify");
    let receiver = UnixDatagram::bind(&notify_path).unwrap();
    receiver
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let port = common::reserve_tcp_port();
    write_private_file(&config, format!(
        "mode = 'relay'\n[ingress]\nprimary = 'socks5'\n[socks]\nlisten = '127.0.0.1:{port}'\n[direct]\nstate_path = '{}'\n[relay]\nserver = '127.0.0.1:8443'\nauth_token = '{}'\n",
        dir.path().join("state.json").display(), TEST_RELAY_AUTH_TOKEN
    )).unwrap();
    let mut command = client();
    command
        .args(["--config"])
        .arg(&config)
        .args([
            "--no-runtime-events",
            "--forensic-safe",
            "--exit-on-stdin-eof",
            "--json",
        ])
        .env("NOTIFY_SOCKET", &notify_path)
        .stdin(Stdio::piped());
    let mut child = OwnedChild(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut data = [0; 128];
    let n = receiver.recv(&mut data).unwrap();
    assert_eq!(&data[..n], b"READY=1\nSTATUS=Ingress workers ready");
    let mut peer = TcpStream::connect(("127.0.0.1", port)).unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    peer.write_all(&[5, 1, 0]).unwrap();
    let mut greeting = [0; 2];
    peer.read_exact(&mut greeting).unwrap();
    assert_eq!(greeting, [5, 0]);
    drop(peer);
    drop(child.0.stdin.take());
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "client did not stop after stdin EOF"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let _occupied = TcpListener::bind(("127.0.0.1", port)).unwrap();
    let output = run_bounded(&mut command);
    assert!(!output.status.success());
    receiver
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    assert!(matches!(
        receiver.recv(&mut data).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    ));
}

#[test]
fn privacy_plan_refuses_actual_startup_before_relay_listener_or_private_identity() {
    let dir = TestDir::new("privacy-plan-startup-refusal");
    let relay = TcpListener::bind("127.0.0.1:0").unwrap();
    relay.set_nonblocking(true).unwrap();
    // Occupied ingress makes successful refusal distinguishable in the unit
    // loader test; here we additionally observe no relay connection or files.
    let ingress = TcpListener::bind("127.0.0.1:0").unwrap();
    let config = dir.path().join("config.toml");
    let events = dir.path().join("events.jsonl");
    let state = dir.path().join("state.json");
    for request in [
        "packet_modifiers = ['randomized_schedule']",
        "packet_modifiers = ['poisson_schedule']",
        "packet_modifiers = ['mec_control']",
        "packet_modifiers = ['constant_cadence', 'randomized_schedule']",
        "requested_guarantee = 'whole_flow_differential_privacy'",
    ] {
        write_private_file(&config, format!(
            "mode = 'relay'\n[privacy_plan]\n{request}\n[ingress]\nprimary = 'socks5'\n[socks]\nlisten = '{}'\n[direct]\nstate_path = '{}'\n[relay]\nserver = '{}'\nserver_name = 'relay.test'\nauth_token = ''\nca_cert = 'absent-outer.pem'\ntransport_priority = ['grpc_stream']\nudp_transport_priority = []\n[relay.inner_tls]\nserver_name = 'relay.test'\nserver_ca = 'absent-ca.pem'\ncert = 'absent-device.pem'\nkey = 'absent-private.key'\n",
            ingress.local_addr().unwrap(), common::toml_path(&state), relay.local_addr().unwrap()
        )).unwrap();
        for validate in [false, true] {
            let mut command = client();
            command
                .arg("--config")
                .arg(&config)
                .arg("--runtime-events-jsonl")
                .arg(&events)
                .args(["--forensic-safe", "--json"]);
            if validate {
                command.arg("--validate-config");
            }
            let output = run_bounded(&mut command);
            assert!(!output.status.success(), "{request}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("client_failed"), "{stderr}");
            assert!(!stderr.contains("absent-private"), "{stderr}");
            assert!(matches!(
                relay.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            ));
            assert!(!state.exists());
            // Some normal-startup logging may create a private events file;
            // this is not socket/identity readiness and must not be mislabeled.
            if events.exists() {
                let content = std::fs::read_to_string(&events).unwrap();
                assert!(!content.contains("\"kind\":\"ready\""));
                std::fs::remove_file(&events).unwrap();
            }
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}

#[test]
fn diagnostics_only_plan_keeps_existing_validation_wire_and_defaults() {
    let dir = TestDir::new("privacy-plan-compatible");
    let config = dir.path().join("config.toml");
    write_private_file(&config, format!(
        "mode = 'relay'\n[privacy_plan]\ndiagnostics = ['leakage_analysis', 'measured_frontier', 'network_calculus', 'binary_schedule_accountant', 'minimum_entropy_coupling', 'nonstationary_bandit', 'fleet_failure_domains']\n[ingress]\nprimary = 'socks5'\n[relay]\nserver = '127.0.0.1:8443'\nauth_token = '{TEST_RELAY_AUTH_TOKEN}'\n"
    )).unwrap();
    let output = run_bounded(
        client()
            .args(["--validate-config", "--json", "--config"])
            .arg(&config),
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
        serde_json::json!({"schema": "aegis_config_validation_v1", "valid": true})
    );
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
}
