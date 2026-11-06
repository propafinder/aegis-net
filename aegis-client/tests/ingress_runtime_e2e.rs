mod common;

use common::{
    assert_no_event, assert_socks_listener_healthy, event_codes, reserve_tcp_port, wait_for_event,
    wait_for_port, ChildGuard, TestDir, TEST_RELAY_AUTH_TOKEN,
};
#[cfg(target_os = "macos")]
use rcgen::{generate_simple_self_signed, CertifiedKey};
#[cfg(target_os = "linux")]
use serde_json::Value;
#[cfg(target_os = "macos")]
use std::fs;
use std::io::{Read, Write};
#[cfg(target_os = "linux")]
use std::net::TcpListener as StdTcpListener;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::process::Command;
#[cfg(target_os = "linux")]
use std::thread;
use std::time::Duration;
#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(target_os = "macos")]
use std::time::{SystemTime, UNIX_EPOCH};

fn macos_pf_platform_family_supported() -> bool {
    #[cfg(target_os = "macos")]
    {
        true
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

fn windivert_platform_family_supported() -> bool {
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(not(target_os = "windows"))]
    {
        false
    }
}

#[cfg(target_os = "macos")]
struct RelayMasqueServerGuard {
    runtime: tokio::runtime::Runtime,
    server_task: tokio::task::JoinHandle<()>,
    udp_echo_task: tokio::task::JoinHandle<()>,
    cert_path: PathBuf,
    server_addr: String,
    masque_server_addr: String,
    dns_target_port: u16,
}

#[cfg(target_os = "macos")]
impl RelayMasqueServerGuard {
    fn start(dir: &Path) -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let cert_dir = dir.join(format!("relay-masque-certs-{unique}"));
        fs::create_dir_all(&cert_dir).expect("create relay cert dir");
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(vec!["localhost".into()]).expect("generate relay cert");
        let cert_path = cert_dir.join("cert.pem");
        let key_path = cert_dir.join("key.pem");
        common::write_private_file(&cert_path, cert.pem()).expect("write relay cert");
        common::write_private_file(&key_path, key_pair.serialize_pem()).expect("write relay key");

        let tcp_port = reserve_tcp_port();
        let quic_port = {
            std::net::UdpSocket::bind("127.0.0.1:0")
                .expect("bind udp port")
                .local_addr()
                .expect("udp local addr")
                .port()
        };
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("build relay runtime");
        let (dns_target_port, udp_echo_task) = runtime.block_on(async {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("bind udp echo");
            let port = socket.local_addr().expect("udp echo addr").port();
            let task = tokio::spawn(async move {
                let mut buf = [0u8; 2048];
                loop {
                    let Ok((n, peer)) = socket.recv_from(&mut buf).await else {
                        break;
                    };
                    if socket.send_to(&buf[..n], peer).await.is_err() {
                        break;
                    }
                }
            });
            (port, task)
        });
        let server_cfg = aegis_server::config::ServerConfig {
            listen: format!("127.0.0.1:{tcp_port}"),
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
            transport: aegis_server::config::TransportConfig {
                quic_listen: Some(format!("127.0.0.1:{quic_port}")),
                ..Default::default()
            },
            bundle_endpoint: Default::default(),
        };
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server_task = runtime.spawn(async move {
            let _ = aegis_server::run_server_with_ready(server_cfg, Some(ready_tx)).await;
        });
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), ready_rx)
                .await
                .expect("relay readiness timeout")
                .expect("relay stopped before readiness");
        });

        Self {
            runtime,
            server_task,
            udp_echo_task,
            cert_path,
            server_addr: format!("127.0.0.1:{tcp_port}"),
            masque_server_addr: format!("127.0.0.1:{quic_port}"),
            dns_target_port,
        }
    }
}

#[cfg(target_os = "macos")]
impl Drop for RelayMasqueServerGuard {
    fn drop(&mut self) {
        self.server_task.abort();
        self.udp_echo_task.abort();
        self.runtime.block_on(async {
            tokio::task::yield_now().await;
        });
    }
}

#[cfg(target_os = "macos")]
#[allow(clippy::too_many_arguments)]
fn apply_macos_pf_helper_state(
    state_path: &Path,
    listen: &str,
    redirect_from: &str,
    target: &str,
    dns_redirect_from: Option<&str>,
    dns_target: Option<&str>,
    system_wide_enabled: bool,
    prepared_boundary_enabled: bool,
) {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root");
    let helper = repo_root.join("scripts/macos-wide-pf.sh");
    let mut command = Command::new("bash");
    command
        .arg(helper)
        .arg("apply")
        .arg("--json")
        .env("AEGIS_MACOS_PF_HELPER_UNAME", "Darwin")
        .env("AEGIS_MACOS_PF_HELPER_APPLY_MODE", "simulate")
        .env("AEGIS_MACOS_PF_HELPER_PFCTL_BIN", "true")
        .env("AEGIS_MACOS_PF_HELPER_IFCONFIG_BIN", "true")
        .env("AEGIS_MACOS_PF_HELPER_ROUTE_BIN", "true")
        .env("AEGIS_MACOS_PF_STATE_PATH", state_path)
        .env("AEGIS_MACOS_PF_LISTEN", listen)
        .env("AEGIS_MACOS_PF_REDIRECT_FROM", redirect_from)
        .env("AEGIS_MACOS_PF_TARGET", target);
    if let Some(value) = dns_redirect_from {
        command.env("AEGIS_MACOS_PF_DNS_PREVIEW_ENABLED", "1");
        command.env("AEGIS_MACOS_PF_DNS_REDIRECT_FROM", value);
    }
    if let Some(value) = dns_target {
        command.env("AEGIS_MACOS_PF_DNS_TARGET", value);
    }
    if system_wide_enabled {
        command.env("AEGIS_MACOS_PF_SYSTEM_WIDE_ENABLED", "1");
    }
    if prepared_boundary_enabled {
        command.env("AEGIS_MACOS_PF_PREPARED_BOUNDARY_ENABLED", "1");
    }
    let output = command.output().expect("run macos pf helper");
    if !output.status.success() {
        panic!(
            "macos-wide-pf.sh apply failed: status={:?}\nstdout={}\nstderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[cfg(target_os = "linux")]
fn wait_for_wide_accept_outcome(
    events_path: &std::path::Path,
    needle: &str,
    expected_count: usize,
) -> (Vec<Value>, Vec<Value>) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(records) = common::read_jsonl_records(events_path) {
            let matches: Vec<Value> = records
                .iter()
                .filter(|record| {
                    record["event_code"] == "ingress_accept_failed"
                        && record["fields"]["error"]
                            .as_str()
                            .unwrap_or_default()
                            .contains(needle)
                })
                .cloned()
                .collect();
            if matches.len() >= expected_count {
                return (matches, records);
            }
            if Instant::now() >= deadline {
                return (matches, records);
            }
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[cfg(target_os = "linux")]
fn wait_for_v6_port(port: u16, timeout: Duration) -> std::net::TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match std::net::TcpStream::connect(("::1", port)) {
            Ok(stream) => return stream,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                thread::sleep(Duration::from_millis(100));
            }
            Err(err) => panic!("wide IPv6 listener did not start on port {port}: {err}"),
        }
    }
}

fn parse_ipv4_listen_port(value: &serde_json::Value) -> u16 {
    let listen = value.as_str().expect("listen string");
    let addr: std::net::SocketAddr = listen.parse().expect("socket addr");
    match addr {
        std::net::SocketAddr::V4(addr) => addr.port(),
        std::net::SocketAddr::V6(_) => panic!("expected ipv4 listen addr, got {listen}"),
    }
}

fn wait_for_started_socks_fallback_port(
    events_path: &std::path::Path,
    expected_reason_code: &str,
) -> u16 {
    let (_fallback, records) = wait_for_event(
        events_path,
        "ingress_startup_fallback_selected",
        Duration::from_secs(10),
    );
    let fallback = records
        .iter()
        .rev()
        .find(|record| record["event_code"] == "ingress_startup_fallback_selected")
        .expect("startup fallback event");
    assert_eq!(fallback["fields"]["listen"], "127.0.0.1:0");
    assert_eq!(
        fallback["fields"]["fallback_reason_code"],
        expected_reason_code
    );

    let (started, _records) = wait_for_event(
        events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        expected_reason_code
    );

    // Fallback selection records the requested listen address; runtime traffic
    // must follow the post-bind backend_started address to hit the live socket.
    let actual_port = parse_ipv4_listen_port(&started["fields"]["listen"]);
    assert_ne!(actual_port, 0);
    actual_port
}

#[test]
fn unsupported_socks_command_runtime_jsonl_e2e() {
    let td = TestDir::new("unsupported-command");
    let events_path = td.path().join("unsupported-command.jsonl");
    let cfg_path = td.path().join("unsupported-command.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
        .expect("write unsupported request");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(&reply[..2], b"\x05\x07");
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_accept_failed",
        Duration::from_secs(10),
    );
    let accept_fail = records
        .iter()
        .find(|record| {
            record["event_code"] == "ingress_accept_failed"
                && record["fields"]["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("socks5_request_read: unsupported socks5 command")
        })
        .expect("unsupported command accept failure");
    assert_eq!(accept_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(accept_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(accept_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(accept_fail["fields"]["mode"], "Direct");
    assert_eq!(
        accept_fail["fields"]["wide_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["rollout_profile"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(accept_fail["fields"]["accept_error_kind"], "invalid_data");

    assert_socks_listener_healthy(socks_port);
}

#[test]
fn pure_socks_startup_runtime_jsonl_omits_wide_rollout_hints() {
    let td = TestDir::new("pure-socks-startup");
    let events_path = td.path().join("pure-socks-startup.jsonl");
    let cfg_path = td.path().join("pure-socks-startup.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (started, records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(started["fields"]["requested_primary"], "Socks5");
    assert_eq!(
        started["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );

    let plan = records
        .iter()
        .find(|record| record["event_code"] == "ingress_startup_plan_evaluated")
        .expect("startup plan event");
    assert_eq!(plan["fields"]["requested_primary"], "Socks5");
    assert_eq!(plan["fields"]["selected_backend"], "Socks5Fallback");
    assert_eq!(
        plan["fields"]["fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(plan["fields"]["fallback_reason"], serde_json::Value::Null);
    assert_eq!(plan["fields"]["wide_enabled"], serde_json::Value::Null);
    assert_eq!(plan["fields"]["wide_supported"], serde_json::Value::Null);
    assert_eq!(
        plan["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(plan["fields"]["wide_platform"], serde_json::Value::Null);
    assert_eq!(
        plan["fields"]["wide_platform_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan["fields"]["wide_rollout_profile"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan["fields"]["wide_rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan["fields"]["wide_prerouting_interface"],
        serde_json::Value::Null
    );
    assert_eq!(plan["fields"]["wide_listen"], serde_json::Value::Null);
    assert_eq!(
        plan["fields"]["wide_backend_current_stage"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan["fields"]["wide_backend_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        plan["fields"]["wide_backend_scope_target"],
        serde_json::Value::Null
    );

    assert_no_event(&records, "ingress_preflight_hint");
    assert_no_event(&records, "ingress_startup_fallback_selected");
    assert_no_event(&records, "ingress_startup_selection_failed");

    assert_socks_listener_healthy(socks_port);
}

#[test]
fn wide_disabled_falls_back_to_socks_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-disabled-fallback");
    let events_path = td.path().join("wide-disabled-fallback.jsonl");
    let cfg_path = td.path().join("wide-disabled-fallback.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = false
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_startup_fallback_selected",
        Duration::from_secs(10),
    );
    let fallback = records
        .iter()
        .find(|record| record["event_code"] == "ingress_startup_fallback_selected")
        .expect("startup fallback event");
    assert_eq!(
        fallback["fields"]["fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(fallback["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(fallback["fields"]["wide_supported"], false);
    assert_eq!(fallback["fields"]["wide_platform_family_supported"], false);

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(started["fields"]["backend_runtime_id"], "socks5_fallback");
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(started["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(
        started["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_support_tier"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_policy"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );
    assert_eq!(started["fields"]["wide_dns_port"], serde_json::Value::Null);

    assert_socks_listener_healthy(socks_port);
}

#[test]
fn wide_disabled_fallback_backend_started_reports_actual_dynamic_socks_listen() {
    let td = TestDir::new("wide-disabled-fallback-dynamic-listen");
    let events_path = td
        .path()
        .join("wide-disabled-fallback-dynamic-listen.jsonl");
    let cfg_path = td.path().join("wide-disabled-fallback-dynamic-listen.toml");

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = false
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:0"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);
    let actual_port = wait_for_started_socks_fallback_port(&events_path, "wide_disabled_in_config");

    assert_socks_listener_healthy(actual_port);
}

#[test]
fn wide_disabled_fallback_dynamic_listen_session_broker_failure_keeps_wide_context() {
    let td = TestDir::new("wide-disabled-fallback-dynamic-broker-failure");
    let events_path = td
        .path()
        .join("wide-disabled-fallback-dynamic-broker-failure.jsonl");
    let cfg_path = td
        .path()
        .join("wide-disabled-fallback-dynamic-broker-failure.toml");

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = false
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:0"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let actual_port = wait_for_started_socks_fallback_port(&events_path, "wide_disabled_in_config");
    let mut client = wait_for_port(actual_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    let host = b"nonexistent.invalid";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).expect("write connect request");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply[1], 4);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_session_broker_failed",
        Duration::from_secs(10),
    );
    let broker_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_session_broker_failed")
        .expect("broker failure event");
    assert_eq!(broker_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(
        broker_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["requested_primary"], "Wide");
    assert_eq!(broker_fail["fields"]["requested_primary_code"], "wide");
    assert_eq!(broker_fail["fields"]["mode"], "Direct");
    assert_eq!(broker_fail["fields"]["mode_code"], "direct");
    assert_eq!(broker_fail["fields"]["wide_supported"], false);
    assert_eq!(
        broker_fail["fields"]["wide_platform_family_supported"],
        false
    );
    assert_eq!(broker_fail["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(broker_fail["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(
        broker_fail["fields"]["rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(
        broker_fail["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        broker_fail["fields"]["startup_fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(broker_fail["fields"]["broker_error_code"], "resolve_failed");
}

#[test]
fn wide_disabled_fallback_dynamic_listen_relay_tcp_reject_keeps_wide_context() {
    let td = TestDir::new("wide-disabled-fallback-dynamic-relay-reject");
    let events_path = td
        .path()
        .join("wide-disabled-fallback-dynamic-relay-reject.jsonl");
    let cfg_path = td
        .path()
        .join("wide-disabled-fallback-dynamic-relay-reject.toml");

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = false
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:0"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
transport_priority = []
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let actual_port = wait_for_started_socks_fallback_port(&events_path, "wide_disabled_in_config");
    let mut client = wait_for_port(actual_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb")
        .expect("write connect request");
    let mut connect_resp = [0u8; 10];
    client
        .read_exact(&mut connect_resp)
        .expect("read connect response");
    assert_eq!(connect_resp[1], 1);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_tcp_connect_rejected",
        Duration::from_secs(10),
    );
    let reject = records
        .iter()
        .find(|record| record["event_code"] == "ingress_tcp_connect_rejected")
        .expect("relay tcp reject event");
    assert_eq!(reject["fields"]["backend"], "socks5_fallback");
    assert_eq!(reject["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(reject["fields"]["requested_primary"], "Wide");
    assert_eq!(reject["fields"]["requested_primary_code"], "wide");
    assert_eq!(reject["fields"]["mode"], "Relay");
    assert_eq!(reject["fields"]["mode_code"], "relay");
    assert_eq!(reject["fields"]["wide_supported"], false);
    assert_eq!(reject["fields"]["wide_platform_family_supported"], false);
    assert_eq!(reject["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(reject["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(reject["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        reject["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(
        reject["fields"]["reject_reason_code"],
        "tcp_connect_requires_runtime_ready_relay_transport"
    );
}

#[test]
fn wide_macos_pf_falls_back_to_socks_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-macos-pf-fallback");
    let events_path = td.path().join("wide-macos-pf-fallback.jsonl");
    let cfg_path = td.path().join("wide-macos-pf-fallback.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (fallback, records) = wait_for_event(
        &events_path,
        "ingress_startup_fallback_selected",
        Duration::from_secs(10),
    );
    assert_eq!(fallback["fields"]["requested_primary"], "Wide");
    assert_eq!(
        fallback["fields"]["listen"],
        format!("127.0.0.1:{socks_port}")
    );
    assert_eq!(
        fallback["fields"]["fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(fallback["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(
        fallback["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(fallback["fields"]["wide_supported"], false);
    assert_eq!(
        fallback["fields"]["wide_platform_family_supported"],
        macos_pf_platform_family_supported()
    );
    assert_eq!(fallback["fields"]["wide_platform"], "MacosPf");

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(
        started["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(
        started["fields"]["wide_platform_family_supported"],
        macos_pf_platform_family_supported()
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_support_tier"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_policy"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );
    assert_eq!(started["fields"]["wide_dns_port"], serde_json::Value::Null);
    assert_no_event(&records, "ingress_startup_selection_failed");

    assert_socks_listener_healthy(socks_port);
}

#[test]
fn wide_macos_pf_fallback_session_broker_failure_keeps_wide_context() {
    let td = TestDir::new("wide-macos-pf-fallback-broker-failure");
    let events_path = td
        .path()
        .join("wide-macos-pf-fallback-broker-failure.jsonl");
    let cfg_path = td.path().join("wide-macos-pf-fallback-broker-failure.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    let host = b"nonexistent.invalid";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).expect("write connect request");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply[1], 4);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_session_broker_failed",
        Duration::from_secs(10),
    );
    let broker_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_session_broker_failed")
        .expect("broker failure event");
    assert_eq!(broker_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(
        broker_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["requested_primary"], "Wide");
    assert_eq!(broker_fail["fields"]["requested_primary_code"], "wide");
    assert_eq!(broker_fail["fields"]["mode"], "Direct");
    assert_eq!(broker_fail["fields"]["mode_code"], "direct");
    assert_eq!(broker_fail["fields"]["wide_supported"], false);
    assert_eq!(
        broker_fail["fields"]["wide_platform_family_supported"],
        macos_pf_platform_family_supported()
    );
    assert_eq!(
        broker_fail["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(broker_fail["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(
        broker_fail["fields"]["rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(
        broker_fail["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        broker_fail["fields"]["startup_fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(broker_fail["fields"]["broker_error_code"], "resolve_failed");
}

#[test]
fn wide_macos_pf_without_fallback_reports_selection_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-macos-pf-no-fallback");
    let events_path = td.path().join("wide-macos-pf-no-fallback.jsonl");
    let cfg_path = td.path().join("wide-macos-pf-no-fallback.toml");

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:1080"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (failed, records) = wait_for_event(
        &events_path,
        "ingress_startup_selection_failed",
        Duration::from_secs(10),
    );
    assert_eq!(failed["fields"]["requested_primary"], "Wide");
    assert_eq!(
        failed["fields"]["selection_error_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(
        failed["fields"]["selection_hint_code"],
        "use_supported_backend_or_allow_fallback"
    );
    assert_eq!(
        failed["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(failed["fields"]["wide_supported"], false);
    assert_eq!(
        failed["fields"]["wide_platform_family_supported"],
        macos_pf_platform_family_supported()
    );
    assert_eq!(failed["fields"]["wide_platform"], "MacosPf");
    assert_no_event(&records, "ingress_backend_started");
    assert_no_event(&records, "ingress_startup_fallback_selected");
}

#[cfg(target_os = "macos")]
#[test]
fn wide_macos_pf_system_wide_boundary_without_fallback_reports_selection_failure() {
    let td = TestDir::new("wide-macos-pf-system-wide-boundary-no-fallback");
    let events_path = td
        .path()
        .join("wide-macos-pf-system-wide-boundary-no-fallback.jsonl");
    let cfg_path = td
        .path()
        .join("wide-macos-pf-system-wide-boundary-no-fallback.toml");
    let state_path = td.path().join("macos-pf-system-wide-boundary-state.json");

    apply_macos_pf_helper_state(
        &state_path,
        "0.0.0.0:15080",
        "10.10.0.5:28084",
        "1.1.1.1:53",
        None,
        None,
        true,
        false,
    );

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
default_mark = 0

[socks]
listen = "127.0.0.1:1080"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let state_path_env = state_path.to_string_lossy().into_owned();
    let _client = ChildGuard::spawn_with_env(
        &cfg_path,
        &events_path,
        &[("AEGIS_MACOS_PF_STATE_PATH", state_path_env.as_str())],
    );

    let (failed, records) = wait_for_event(
        &events_path,
        "ingress_startup_selection_failed",
        Duration::from_secs(10),
    );
    assert_eq!(failed["fields"]["requested_primary"], "Wide");
    assert_eq!(
        failed["fields"]["selection_error_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
        failed["fields"]["selection_hint_code"],
        "use_supported_backend_or_allow_fallback"
    );
    assert_eq!(
        failed["fields"]["reason"],
        "wide ingress is selected, but unavailable: macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
    );
    assert_eq!(
        failed["fields"]["hint"],
        "macos_pf system_wide_phase3 is currently boundary-only; allow fallback or stay on the narrower tcp_only/dns_preview contours while testing"
    );
    assert_eq!(
        failed["fields"]["wide_udp_capture_contract_requested"],
        "generic_capture_unstable"
    );
    assert_eq!(
        failed["fields"]["wide_udp_capture_support_tier_requested"],
        "guarded_unstable"
    );
    assert_eq!(failed["fields"]["wide_runtime_readiness"], "boundary_only");
    assert_eq!(failed["fields"]["wide_supported"], false);
    assert_eq!(failed["fields"]["wide_platform_family_supported"], true);
    assert_eq!(failed["fields"]["wide_platform"], "MacosPf");
    assert_no_event(&records, "ingress_backend_started");
    assert_no_event(&records, "ingress_startup_fallback_selected");
}

#[cfg(target_os = "macos")]
#[test]
fn wide_macos_pf_system_wide_boundary_falls_back_to_socks_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-macos-pf-system-wide-boundary-fallback");
    let events_path = td
        .path()
        .join("wide-macos-pf-system-wide-boundary-fallback.jsonl");
    let cfg_path = td
        .path()
        .join("wide-macos-pf-system-wide-boundary-fallback.toml");
    let state_path = td.path().join("macos-pf-system-wide-boundary-state.json");

    apply_macos_pf_helper_state(
        &state_path,
        "0.0.0.0:15080",
        "10.10.0.5:28084",
        "1.1.1.1:53",
        None,
        None,
        true,
        false,
    );

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "0.0.0.0:15080"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let state_path_env = state_path.to_string_lossy().into_owned();
    let _client = ChildGuard::spawn_with_env(
        &cfg_path,
        &events_path,
        &[("AEGIS_MACOS_PF_STATE_PATH", state_path_env.as_str())],
    );

    let (fallback, records) = wait_for_event(
        &events_path,
        "ingress_startup_fallback_selected",
        Duration::from_secs(10),
    );
    assert_eq!(fallback["fields"]["requested_primary"], "Wide");
    assert_eq!(
        fallback["fields"]["fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
        fallback["fields"]["reason"],
        "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
    );
    assert_eq!(fallback["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(
        fallback["fields"]["wide_runtime_readiness"],
        "boundary_only"
    );
    assert_eq!(fallback["fields"]["wide_supported"], false);
    assert_eq!(fallback["fields"]["wide_platform_family_supported"], true);
    assert_eq!(fallback["fields"]["wide_platform"], "MacosPf");
    assert_eq!(
        fallback["fields"]["wide_backend_current_stage"],
        "system_wide_phase3_boundary"
    );
    assert_eq!(
        fallback["fields"]["wide_backend_scope_target"],
        "system_wide_phase3"
    );
    assert_eq!(
        fallback["fields"]["wide_backend_reason_code"],
        "pf_system_wide_phase3_boundary_only"
    );

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
        started["fields"]["startup_fallback_reason"],
        "macos_pf system_wide_phase3 is currently boundary-only and falls back until a broader runtime path exists"
    );
    assert_eq!(started["fields"]["wide_runtime_readiness"], "boundary_only");
    assert_eq!(started["fields"]["wide_platform_family_supported"], true);
    assert_eq!(
        started["fields"]["wide_backend_current_stage"],
        "system_wide_phase3_boundary"
    );
    assert_eq!(
        started["fields"]["wide_backend_scope_target"],
        "system_wide_phase3"
    );
    assert_eq!(
        started["fields"]["wide_backend_reason_code"],
        "pf_system_wide_phase3_boundary_only"
    );
    assert_no_event(&records, "ingress_startup_selection_failed");

    assert_socks_listener_healthy(socks_port);
}

#[cfg(target_os = "macos")]
#[test]
fn wide_macos_pf_system_wide_prepared_boundary_falls_back_to_socks_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-macos-pf-system-wide-prepared-boundary-fallback");
    let events_path = td
        .path()
        .join("wide-macos-pf-system-wide-prepared-boundary-fallback.jsonl");
    let cfg_path = td
        .path()
        .join("wide-macos-pf-system-wide-prepared-boundary-fallback.toml");
    let state_path = td
        .path()
        .join("macos-pf-system-wide-prepared-boundary-state.json");

    apply_macos_pf_helper_state(
        &state_path,
        "0.0.0.0:15081",
        "10.10.0.6:28085",
        "8.8.8.8:53",
        None,
        None,
        true,
        true,
    );

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "0.0.0.0:15081"
capture_dns = true
udp_capture_contract = "generic_capture_unstable"
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let state_path_env = state_path.to_string_lossy().into_owned();
    let _client = ChildGuard::spawn_with_env(
        &cfg_path,
        &events_path,
        &[("AEGIS_MACOS_PF_STATE_PATH", state_path_env.as_str())],
    );

    let (fallback, records) = wait_for_event(
        &events_path,
        "ingress_startup_fallback_selected",
        Duration::from_secs(10),
    );
    assert_eq!(fallback["fields"]["requested_primary"], "Wide");
    assert_eq!(
        fallback["fields"]["fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
        fallback["fields"]["reason"],
        "macos_pf system_wide_phase3 is currently prepared-boundary-only and falls back until a broader runtime path exists"
    );
    assert_eq!(fallback["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(
        fallback["fields"]["wide_runtime_readiness"],
        "prepared_boundary"
    );
    assert_eq!(fallback["fields"]["wide_supported"], false);
    assert_eq!(fallback["fields"]["wide_platform_family_supported"], true);
    assert_eq!(fallback["fields"]["wide_platform"], "MacosPf");
    assert_eq!(
        fallback["fields"]["wide_backend_current_stage"],
        "system_wide_phase3_prepared_boundary"
    );
    assert_eq!(
        fallback["fields"]["wide_backend_scope_target"],
        "system_wide_phase3"
    );
    assert_eq!(
        fallback["fields"]["wide_backend_reason_code"],
        "pf_system_wide_phase3_prepared_boundary_only"
    );

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        "wide_backend_boundary_only"
    );
    assert_eq!(
        started["fields"]["startup_fallback_reason"],
        "macos_pf system_wide_phase3 is currently prepared-boundary-only and falls back until a broader runtime path exists"
    );
    assert_eq!(
        started["fields"]["wide_runtime_readiness"],
        "prepared_boundary"
    );
    assert_eq!(started["fields"]["wide_platform_family_supported"], true);
    assert_eq!(
        started["fields"]["wide_backend_current_stage"],
        "system_wide_phase3_prepared_boundary"
    );
    assert_eq!(
        started["fields"]["wide_backend_scope_target"],
        "system_wide_phase3"
    );
    assert_eq!(
        started["fields"]["wide_backend_reason_code"],
        "pf_system_wide_phase3_prepared_boundary_only"
    );
    assert_no_event(&records, "ingress_startup_selection_failed");

    assert_socks_listener_healthy(socks_port);
}

#[cfg(target_os = "macos")]
#[test]
fn wide_macos_pf_tcp_only_active_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-macos-pf-tcp-only-active");
    let events_path = td.path().join("wide-macos-pf-tcp-only-active.jsonl");
    let cfg_path = td.path().join("wide-macos-pf-tcp-only-active.toml");
    let state_path = td.path().join("macos-pf-state.json");

    let wide_port = reserve_tcp_port();
    let redirect_port = reserve_tcp_port();

    // Bind first and take the port from the socket, rather than reserving a
    // port and binding it later: in between, the client process binds sockets
    // of its own on port 0 and the kernel can hand it this very port, after
    // which this bind fails. That was this test's flakiness.
    let target_listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind target listener");
    let target_port = target_listener
        .local_addr()
        .expect("target listener addr")
        .port();
    let target_handle = std::thread::spawn(move || {
        let (mut stream, _peer) = target_listener.accept().expect("accept target client");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set target read timeout");
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .expect("set target write timeout");
        let mut buf = [0u8; 512];
        let read = stream.read(&mut buf).expect("read target request");
        let request = String::from_utf8_lossy(&buf[..read]).into_owned();
        stream
            .write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .expect("write target response");
        request
    });

    apply_macos_pf_helper_state(
        &state_path,
        &format!("127.0.0.1:{wide_port}"),
        &format!("127.0.0.1:{redirect_port}"),
        &format!("127.0.0.1:{target_port}"),
        None,
        None,
        false,
        false,
    );

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "127.0.0.1:{wide_port}"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let state_path_env = state_path.to_string_lossy().into_owned();
    let _client = ChildGuard::spawn_with_env(
        &cfg_path,
        &events_path,
        &[("AEGIS_MACOS_PF_STATE_PATH", state_path_env.as_str())],
    );

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "wide_primary");
    assert_eq!(
        started["fields"]["backend_runtime_id"],
        "wide_primary_macos"
    );
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(
        started["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(started["fields"]["wide_supported"], true);
    assert_eq!(started["fields"]["wide_platform_family_supported"], true);
    assert_eq!(started["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(
        started["fields"]["wide_backend_current_stage"],
        "tcp_only_phase1_live"
    );
    assert_eq!(
        started["fields"]["wide_backend_scope_target"],
        "tcp_only_phase1"
    );
    assert_eq!(
        started["fields"]["wide_backend_reason_code"],
        "pf_tcp_only_ready"
    );
    assert_eq!(
        started["fields"]["wide_dns_capture_preview_status"],
        "disabled"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );

    let mut client = std::net::TcpStream::connect(("127.0.0.1", wide_port))
        .expect("connect active macos wide listener");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set client read timeout");
    client
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("set client write timeout");
    client
        .write_all(b"GET /tcp-only-phase1 HTTP/1.0\r\nHost: local.test\r\n\r\n")
        .expect("write client request");
    let mut response = Vec::new();
    client
        .read_to_end(&mut response)
        .expect("read client response");
    assert!(String::from_utf8_lossy(&response).contains("200 OK"));
    assert!(String::from_utf8_lossy(&response).ends_with("ok"));

    let request = target_handle.join().expect("join target thread");
    assert!(request.contains("GET /tcp-only-phase1 HTTP/1.0"));
    assert!(request.contains("Host: local.test"));

    std::thread::sleep(Duration::from_millis(300));
    let records = common::read_jsonl_records(&events_path).expect("read runtime events");
    assert_no_event(&records, "ingress_startup_selection_failed");
    assert_no_event(&records, "ingress_startup_fallback_selected");
    assert_no_event(&records, "ingress_wide_bind_fallback");
    assert_no_event(&records, "ingress_accept_failed");
    assert_no_event(&records, "ingress_session_broker_failed");
    assert_no_event(&records, "ingress_tcp_connect_rejected");
}

#[cfg(target_os = "macos")]
#[test]
fn wide_macos_pf_dns_preview_active_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-macos-pf-dns-preview-active");
    let events_path = td.path().join("wide-macos-pf-dns-preview-active.jsonl");
    let cfg_path = td.path().join("wide-macos-pf-dns-preview-active.toml");
    let state_path = td.path().join("macos-pf-dns-state.json");
    let relay = RelayMasqueServerGuard::start(td.path());

    let wide_port = reserve_tcp_port();
    let redirect_port = reserve_tcp_port();
    let target_port = reserve_tcp_port();
    let dns_redirect_port = {
        std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("bind dns redirect probe")
            .local_addr()
            .expect("dns redirect probe addr")
            .port()
    };

    apply_macos_pf_helper_state(
        &state_path,
        &format!("127.0.0.1:{wide_port}"),
        &format!("127.0.0.1:{redirect_port}"),
        &format!("127.0.0.1:{target_port}"),
        Some(&format!("127.0.0.1:{dns_redirect_port}")),
        Some(&format!("127.0.0.1:{}", relay.dns_target_port)),
        false,
        false,
    );

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "relay"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "127.0.0.1:{wide_port}"
capture_dns = true
dns_port = {dns_port}
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "{relay_server}"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
ca_cert = "{ca_cert}"
transport_priority = ["masque_derived"]
masque_server = "{masque_server}"
"#,
            dns_port = relay.dns_target_port,
            relay_server = relay.server_addr,
            ca_cert = common::toml_path(&relay.cert_path),
            masque_server = relay.masque_server_addr,
        ),
    )
    .expect("write dns preview config");

    let state_path_env = state_path.to_string_lossy().into_owned();
    let _client = ChildGuard::spawn_with_env(
        &cfg_path,
        &events_path,
        &[("AEGIS_MACOS_PF_STATE_PATH", state_path_env.as_str())],
    );

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "wide_primary");
    assert_eq!(
        started["fields"]["backend_runtime_id"],
        "wide_primary_macos"
    );
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(
        started["fields"]["startup_path_code"],
        "wide_primary_started"
    );
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(started["fields"]["wide_supported"], true);
    assert_eq!(started["fields"]["wide_platform_family_supported"], true);
    assert_eq!(started["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(
        started["fields"]["wide_backend_current_stage"],
        "dns_preview_phase2_live"
    );
    assert_eq!(
        started["fields"]["wide_backend_scope_target"],
        "dns_preview_phase2"
    );
    assert_eq!(
        started["fields"]["wide_backend_reason_code"],
        "pf_dns_preview_ready"
    );
    assert_eq!(
        started["fields"]["wide_dns_capture_preview_status"],
        "active"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_contract"],
        "preview_allowlist_only"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_support_tier"],
        "supported_preview"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_runtime_scope"],
        "macos_ipv4_loopback_preview"
    );
    assert_eq!(
        started["fields"]["wide_udp_preview_policy"],
        "allowlist_ports"
    );
    assert_eq!(started["fields"]["wide_dns_port"], relay.dns_target_port);
    assert_eq!(
        started["fields"]["wide_udp_preview_ports"],
        serde_json::json!([relay.dns_target_port])
    );

    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind dns preview client");
    udp.set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set udp read timeout");
    let payload = b"\x12\x34macos-dns-preview";
    udp.send_to(payload, ("127.0.0.1", wide_port))
        .expect("send dns preview datagram");
    let mut response = [0u8; 256];
    let (n, _peer) = udp
        .recv_from(&mut response)
        .expect("receive dns preview response");
    assert_eq!(&response[..n], payload);

    let (completed, records) = wait_for_event(
        &events_path,
        "ingress_udp_datagram_completed",
        Duration::from_secs(10),
    );
    assert_eq!(completed["fields"]["backend"], "wide_primary");
    assert_eq!(
        completed["fields"]["backend_runtime_id"],
        "wide_primary_macos"
    );
    assert_eq!(completed["fields"]["target_host"], "127.0.0.1");
    assert_eq!(completed["fields"]["target_port"], relay.dns_target_port);
    assert_eq!(completed["fields"]["response_action"], "local_udp");
    assert_eq!(
        completed["fields"]["wide_udp_capture_contract"],
        "preview_allowlist_only"
    );
    assert_eq!(
        completed["fields"]["wide_udp_capture_support_tier"],
        "supported_preview"
    );
    assert_eq!(
        completed["fields"]["wide_udp_capture_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        completed["fields"]["wide_udp_capture_runtime_scope"],
        "macos_ipv4_loopback_preview"
    );
    assert_eq!(
        completed["fields"]["wide_udp_capture_match_kind"],
        "dns_port"
    );
    assert_eq!(
        completed["fields"]["wide_udp_capture_accept_reason_code"],
        "matched_dns_port_allowlist"
    );
    assert_eq!(
        completed["fields"]["wide_udp_preview_policy"],
        "allowlist_ports"
    );
    assert_eq!(
        completed["fields"]["wide_udp_preview_match_kind"],
        "dns_port"
    );
    assert_eq!(
        completed["fields"]["wide_udp_preview_accept_reason_code"],
        "matched_dns_port_allowlist"
    );
    assert_eq!(
        completed["fields"]["wide_udp_preview_ports"],
        serde_json::json!([relay.dns_target_port])
    );

    assert_no_event(&records, "ingress_startup_selection_failed");
    assert_no_event(&records, "ingress_startup_fallback_selected");
    assert_no_event(&records, "ingress_wide_bind_fallback");
    assert_no_event(&records, "ingress_accept_failed");
    assert_no_event(&records, "ingress_udp_datagram_dropped");
    assert_no_event(&records, "relay_transport_failed");
}

#[cfg(target_os = "linux")]
#[test]
fn wide_prerouting_scoped_without_interface_reports_requested_but_not_effective_capture() {
    let td = TestDir::new("wide-prerouting-scoped-requires-interface");
    let events_path = td
        .path()
        .join("wide-prerouting-scoped-requires-interface.jsonl");
    let cfg_path = td
        .path()
        .join("wide-prerouting-scoped-requires-interface.toml");

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "linux_redirect"
rollout_profile = "prerouting_scoped"
listen = "0.0.0.0:0"
capture_dns = true
default_mark = 0

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (failed, records) = wait_for_event(
        &events_path,
        "ingress_startup_selection_failed",
        Duration::from_secs(10),
    );
    assert_eq!(failed["fields"]["requested_primary"], "Wide");
    assert_eq!(
        failed["fields"]["selection_error_code"],
        "rollout_profile_prerequisites"
    );
    assert_eq!(
        failed["fields"]["selection_hint_code"],
        "set_prerouting_interface_or_switch_rollout_profile"
    );
    assert_eq!(failed["fields"]["wide_runtime_readiness"], "config_error");
    assert_eq!(failed["fields"]["wide_supported"], true);
    assert_eq!(failed["fields"]["wide_platform_family_supported"], true);
    assert_eq!(failed["fields"]["wide_platform"], "LinuxRedirect");
    assert_eq!(failed["fields"]["wide_rollout_profile"], "PreroutingScoped");
    assert_eq!(failed["fields"]["wide_prerouting_interface"], Value::Null);
    assert_eq!(
        failed["fields"]["wide_udp_capture_contract_requested"],
        "preview_allowlist_only"
    );
    assert_eq!(
        failed["fields"]["wide_udp_capture_support_tier_requested"],
        "supported_preview"
    );
    assert_eq!(failed["fields"]["wide_udp_capture_contract"], Value::Null);
    assert_eq!(
        failed["fields"]["wide_udp_capture_support_tier"],
        Value::Null
    );
    assert_eq!(failed["fields"]["wide_udp_capture_policy"], Value::Null);
    assert_eq!(
        failed["fields"]["wide_udp_capture_runtime_scope"],
        Value::Null
    );
    assert_no_event(&records, "ingress_backend_started");
    assert_no_event(&records, "ingress_startup_fallback_selected");
}

#[test]
fn wide_disabled_fallback_session_broker_failure_keeps_wide_context() {
    let td = TestDir::new("wide-disabled-fallback-broker-failure");
    let events_path = td
        .path()
        .join("wide-disabled-fallback-broker-failure.jsonl");
    let cfg_path = td.path().join("wide-disabled-fallback-broker-failure.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = false
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    let host = b"nonexistent.invalid";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).expect("write connect request");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply[1], 4);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_session_broker_failed",
        Duration::from_secs(10),
    );
    let broker_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_session_broker_failed")
        .expect("broker failure event");
    assert_eq!(broker_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(
        broker_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["requested_primary"], "Wide");
    assert_eq!(broker_fail["fields"]["requested_primary_code"], "wide");
    assert_eq!(broker_fail["fields"]["mode"], "Direct");
    assert_eq!(broker_fail["fields"]["mode_code"], "direct");
    assert_eq!(broker_fail["fields"]["wide_supported"], false);
    assert_eq!(
        broker_fail["fields"]["wide_platform_family_supported"],
        false
    );
    assert_eq!(broker_fail["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(broker_fail["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(
        broker_fail["fields"]["rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(
        broker_fail["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        broker_fail["fields"]["startup_fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(broker_fail["fields"]["broker_error_code"], "resolve_failed");
}

#[test]
fn wide_disabled_fallback_relay_tcp_reject_keeps_wide_context() {
    let td = TestDir::new("wide-disabled-fallback-relay-tcp-reject");
    let events_path = td
        .path()
        .join("wide-disabled-fallback-relay-tcp-reject.jsonl");
    let cfg_path = td
        .path()
        .join("wide-disabled-fallback-relay-tcp-reject.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = false
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
transport_priority = []
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb")
        .expect("write connect request");
    let mut connect_resp = [0u8; 10];
    client
        .read_exact(&mut connect_resp)
        .expect("read connect response");
    assert_eq!(connect_resp[1], 1);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_tcp_connect_rejected",
        Duration::from_secs(10),
    );
    let reject = records
        .iter()
        .find(|record| record["event_code"] == "ingress_tcp_connect_rejected")
        .expect("relay tcp reject event");
    assert_eq!(reject["fields"]["backend"], "socks5_fallback");
    assert_eq!(reject["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(reject["fields"]["requested_primary"], "Wide");
    assert_eq!(reject["fields"]["requested_primary_code"], "wide");
    assert_eq!(reject["fields"]["mode"], "Relay");
    assert_eq!(reject["fields"]["mode_code"], "relay");
    assert_eq!(reject["fields"]["wide_supported"], false);
    assert_eq!(reject["fields"]["wide_platform_family_supported"], false);
    assert_eq!(reject["fields"]["wide_runtime_readiness"], "disabled");
    assert_eq!(reject["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(reject["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        reject["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason_code"],
        "wide_disabled_in_config"
    );
    assert_eq!(
        reject["fields"]["reject_reason_code"],
        "tcp_connect_requires_runtime_ready_relay_transport"
    );
}

#[test]
fn wide_windivert_falls_back_to_socks_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-windivert-fallback");
    let events_path = td.path().join("wide-windivert-fallback.jsonl");
    let cfg_path = td.path().join("wide-windivert-fallback.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "windivert"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (fallback, records) = wait_for_event(
        &events_path,
        "ingress_startup_fallback_selected",
        Duration::from_secs(10),
    );
    assert_eq!(fallback["fields"]["requested_primary"], "Wide");
    assert_eq!(
        fallback["fields"]["listen"],
        format!("127.0.0.1:{socks_port}")
    );
    assert_eq!(
        fallback["fields"]["fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(fallback["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(
        fallback["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(fallback["fields"]["wide_supported"], false);
    assert_eq!(
        fallback["fields"]["wide_platform_family_supported"],
        windivert_platform_family_supported()
    );
    assert_eq!(fallback["fields"]["wide_platform"], "Windivert");

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(
        started["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(
        started["fields"]["wide_platform_family_supported"],
        windivert_platform_family_supported()
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_support_tier"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_policy"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );
    assert_eq!(started["fields"]["wide_dns_port"], serde_json::Value::Null);
    assert_no_event(&records, "ingress_startup_selection_failed");

    assert_socks_listener_healthy(socks_port);
}

#[test]
fn wide_windivert_fallback_session_broker_failure_keeps_wide_context() {
    let td = TestDir::new("wide-windivert-fallback-broker-failure");
    let events_path = td
        .path()
        .join("wide-windivert-fallback-broker-failure.jsonl");
    let cfg_path = td
        .path()
        .join("wide-windivert-fallback-broker-failure.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "windivert"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    let host = b"nonexistent.invalid";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).expect("write connect request");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply[1], 4);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_session_broker_failed",
        Duration::from_secs(10),
    );
    let broker_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_session_broker_failed")
        .expect("broker failure event");
    assert_eq!(broker_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(
        broker_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["requested_primary"], "Wide");
    assert_eq!(broker_fail["fields"]["requested_primary_code"], "wide");
    assert_eq!(broker_fail["fields"]["mode"], "Direct");
    assert_eq!(broker_fail["fields"]["mode_code"], "direct");
    assert_eq!(broker_fail["fields"]["wide_supported"], false);
    assert_eq!(
        broker_fail["fields"]["wide_platform_family_supported"],
        windivert_platform_family_supported()
    );
    assert_eq!(
        broker_fail["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(broker_fail["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(
        broker_fail["fields"]["rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(
        broker_fail["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        broker_fail["fields"]["startup_fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(broker_fail["fields"]["broker_error_code"], "resolve_failed");
}

#[test]
fn wide_macos_pf_fallback_relay_tcp_reject_keeps_wide_context() {
    let td = TestDir::new("wide-macos-pf-fallback-relay-tcp-reject");
    let events_path = td
        .path()
        .join("wide-macos-pf-fallback-relay-tcp-reject.jsonl");
    let cfg_path = td
        .path()
        .join("wide-macos-pf-fallback-relay-tcp-reject.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "macos_pf"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
transport_priority = []
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb")
        .expect("write connect request");
    let mut connect_resp = [0u8; 10];
    client
        .read_exact(&mut connect_resp)
        .expect("read connect response");
    assert_eq!(connect_resp[1], 1);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_tcp_connect_rejected",
        Duration::from_secs(10),
    );
    let reject = records
        .iter()
        .find(|record| record["event_code"] == "ingress_tcp_connect_rejected")
        .expect("relay tcp reject event");
    assert_eq!(reject["fields"]["backend"], "socks5_fallback");
    assert_eq!(reject["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(reject["fields"]["requested_primary"], "Wide");
    assert_eq!(reject["fields"]["requested_primary_code"], "wide");
    assert_eq!(reject["fields"]["mode"], "Relay");
    assert_eq!(reject["fields"]["mode_code"], "relay");
    assert_eq!(reject["fields"]["wide_supported"], false);
    assert_eq!(
        reject["fields"]["wide_platform_family_supported"],
        macos_pf_platform_family_supported()
    );
    assert_eq!(
        reject["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(reject["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(reject["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        reject["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(
        reject["fields"]["reject_reason_code"],
        "tcp_connect_requires_runtime_ready_relay_transport"
    );
}

#[test]
fn wide_windivert_fallback_relay_tcp_reject_keeps_wide_context() {
    let td = TestDir::new("wide-windivert-fallback-relay-tcp-reject");
    let events_path = td
        .path()
        .join("wide-windivert-fallback-relay-tcp-reject.jsonl");
    let cfg_path = td
        .path()
        .join("wide-windivert-fallback-relay-tcp-reject.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "relay"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "windivert"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
transport_priority = []
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb")
        .expect("write connect request");
    let mut connect_resp = [0u8; 10];
    client
        .read_exact(&mut connect_resp)
        .expect("read connect response");
    assert_eq!(connect_resp[1], 1);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_tcp_connect_rejected",
        Duration::from_secs(10),
    );
    let reject = records
        .iter()
        .find(|record| record["event_code"] == "ingress_tcp_connect_rejected")
        .expect("relay tcp reject event");
    assert_eq!(reject["fields"]["backend"], "socks5_fallback");
    assert_eq!(reject["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(reject["fields"]["requested_primary"], "Wide");
    assert_eq!(reject["fields"]["requested_primary_code"], "wide");
    assert_eq!(reject["fields"]["mode"], "Relay");
    assert_eq!(reject["fields"]["mode_code"], "relay");
    assert_eq!(reject["fields"]["wide_supported"], false);
    assert_eq!(
        reject["fields"]["wide_platform_family_supported"],
        windivert_platform_family_supported()
    );
    assert_eq!(
        reject["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(reject["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(reject["fields"]["rollout_profile_code"], "output_only_safe");
    assert_eq!(
        reject["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(
        reject["fields"]["reject_reason_code"],
        "tcp_connect_requires_runtime_ready_relay_transport"
    );
}

#[test]
fn wide_windivert_without_fallback_reports_selection_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-windivert-no-fallback");
    let events_path = td.path().join("wide-windivert-no-fallback.jsonl");
    let cfg_path = td.path().join("wide-windivert-no-fallback.toml");

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "windivert"
listen = "0.0.0.0:15080"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:1080"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (failed, records) = wait_for_event(
        &events_path,
        "ingress_startup_selection_failed",
        Duration::from_secs(10),
    );
    assert_eq!(failed["fields"]["requested_primary"], "Wide");
    assert_eq!(
        failed["fields"]["selection_error_code"],
        "unsupported_wide_backend"
    );
    assert_eq!(
        failed["fields"]["selection_hint_code"],
        "use_supported_backend_or_allow_fallback"
    );
    assert_eq!(
        failed["fields"]["wide_runtime_readiness"],
        "unsupported_adapter"
    );
    assert_eq!(failed["fields"]["wide_supported"], false);
    assert_eq!(
        failed["fields"]["wide_platform_family_supported"],
        windivert_platform_family_supported()
    );
    assert_eq!(failed["fields"]["wide_platform"], "Windivert");
    assert_no_event(&records, "ingress_backend_started");
    assert_no_event(&records, "ingress_startup_fallback_selected");
}

#[test]
fn ingress_session_broker_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("broker-failure");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("broker-failure.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = ""
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    let host = b"nonexistent.invalid";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).expect("write connect request");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply[1], 4);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_session_broker_failed",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"ingress_session_broker_failed"),
        "{records:?}"
    );

    let broker_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_session_broker_failed")
        .expect("broker failure event");
    assert_eq!(broker_fail["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(
        broker_fail["fields"]["ingress_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(broker_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(
        broker_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(broker_fail["fields"]["requested_primary_code"], "socks5");
    assert_eq!(broker_fail["fields"]["mode"], "Direct");
    assert_eq!(broker_fail["fields"]["mode_code"], "direct");
    assert_eq!(
        broker_fail["fields"]["wide_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        broker_fail["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        broker_fail["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(
        broker_fail["fields"]["rollout_profile"],
        serde_json::Value::Null
    );
    assert_eq!(
        broker_fail["fields"]["rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(broker_fail["fields"]["broker_error_code"], "resolve_failed");
    assert_eq!(broker_fail["fields"]["request_kind"], "TcpConnect");
    assert_eq!(broker_fail["fields"]["broker_stage"], "resolve_target");
    assert_eq!(broker_fail["fields"]["target_host"], "nonexistent.invalid");
    assert_eq!(broker_fail["fields"]["target_port"], 443);
    assert!(broker_fail["fields"]["response_action"].is_null());
    assert!(broker_fail["fields"]["error"]
        .as_str()
        .expect("broker error")
        .contains("nonexistent.invalid:443"));
}

#[test]
fn ingress_accept_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("accept-failed");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("accept-failed.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut bad_client = wait_for_port(socks_port, Duration::from_secs(20));
    bad_client
        .write_all(b"\x05")
        .expect("write partial handshake");
    drop(bad_client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_accept_failed",
        Duration::from_secs(10),
    );
    let accept_fail = records
        .iter()
        .find(|record| record["event_code"] == "ingress_accept_failed")
        .expect("accept failure event");
    assert_eq!(accept_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(accept_fail["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(
        accept_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(accept_fail["fields"]["requested_primary"], "Socks5");
    assert_eq!(accept_fail["fields"]["requested_primary_code"], "socks5");
    assert_eq!(accept_fail["fields"]["mode"], "Direct");
    assert_eq!(accept_fail["fields"]["mode_code"], "direct");
    assert_eq!(
        accept_fail["fields"]["wide_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["rollout_profile"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        accept_fail["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        accept_fail["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(accept_fail["fields"]["accept_error_kind"], "unexpected_eof");
    assert!(accept_fail["fields"]["error"]
        .as_str()
        .expect("accept error")
        .contains("socks5_handshake"));

    assert_socks_listener_healthy(socks_port);
}

#[test]
fn udp_associate_reject_runtime_jsonl_e2e() {
    let td = TestDir::new("udp-associate");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("udp-associate.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = ""
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        .expect("write udp associate request");
    let mut udp_resp = [0u8; 10];
    client.read_exact(&mut udp_resp).expect("read udp response");
    assert_eq!(udp_resp[1], 7);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_udp_associate_rejected",
        Duration::from_secs(10),
    );
    let reject = records
        .iter()
        .find(|record| record["event_code"] == "ingress_udp_associate_rejected")
        .expect("udp reject event");
    assert_eq!(reject["fields"]["backend"], "socks5_fallback");
    assert_eq!(reject["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(reject["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(reject["fields"]["requested_primary"], "Socks5");
    assert_eq!(reject["fields"]["requested_primary_code"], "socks5");
    assert_eq!(reject["fields"]["mode"], "Direct");
    assert_eq!(reject["fields"]["mode_code"], "direct");
    assert_eq!(reject["fields"]["rollout_profile"], serde_json::Value::Null);
    assert_eq!(
        reject["fields"]["rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(reject["fields"]["wide_supported"], serde_json::Value::Null);
    assert_eq!(
        reject["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(reject["fields"]["request_kind"], "UdpAssociate");
    assert_eq!(
        reject["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(reject["fields"]["reject_stage"], "pre_broker_runtime_gate");
    assert_eq!(
        reject["fields"]["response_action"],
        "send_command_not_supported"
    );
    assert_eq!(reject["fields"]["response_reply_code"], 7);
    assert_eq!(
        reject["fields"]["reject_reason_code"],
        "udp_associate_requires_relay_mode"
    );
    assert_eq!(
        reject["fields"]["reason"],
        "udp associate requires relay mode"
    );
}

#[test]
fn auto_udp_readiness_runtime_jsonl_e2e() {
    assert_auto_udp_readiness_rejected(None);
}

#[test]
fn auto_grpc_only_udp_associate_rejects_before_dispatch_runtime_jsonl_e2e() {
    assert_auto_udp_readiness_rejected(Some("grpc_datagram"));
}

fn assert_auto_udp_readiness_rejected(udp_transport: Option<&str>) {
    let td = TestDir::new("auto-udp");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("auto-udp.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    let udp_priority = udp_transport
        .map(|family| format!("udp_transport_priority = [\"{family}\"]"))
        .unwrap_or_default();
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "auto"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
transport_priority = ["legacy_tls"]
{udp_priority}
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        .expect("write udp associate request");
    let mut udp_resp = [0u8; 10];
    client.read_exact(&mut udp_resp).expect("read udp response");
    assert_eq!(udp_resp[1], 1);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_udp_associate_rejected",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"ingress_udp_associate_rejected"),
        "{records:?}"
    );
    assert_no_event(&records, "ingress_session_failed");
    assert_no_event(&records, "relay_transport_failed");
    assert_no_event(&records, "relay_transport_selected");

    let reject = records
        .iter()
        .find(|record| record["event_code"] == "ingress_udp_associate_rejected")
        .expect("auto udp reject event");
    assert_eq!(reject["fields"]["backend"], "socks5_fallback");
    assert_eq!(reject["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(reject["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(reject["fields"]["requested_primary"], "Socks5");
    assert_eq!(reject["fields"]["requested_primary_code"], "socks5");
    assert_eq!(reject["fields"]["mode"], "Auto");
    assert_eq!(reject["fields"]["mode_code"], "auto");
    assert_eq!(reject["fields"]["wide_supported"], serde_json::Value::Null);
    assert_eq!(
        reject["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(reject["fields"]["rollout_profile"], serde_json::Value::Null);
    assert_eq!(
        reject["fields"]["rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(reject["fields"]["request_kind"], "UdpAssociate");
    assert_eq!(reject["fields"]["reject_stage"], "pre_broker_runtime_gate");
    assert_eq!(reject["fields"]["response_action"], "send_general_failure");
    assert_eq!(reject["fields"]["response_reply_code"], 1);
    assert_eq!(
        reject["fields"]["reject_reason_code"],
        "udp_associate_requires_udp_capable_relay_transport"
    );
    assert_eq!(
        reject["fields"]["reason"],
        "udp associate requires a configured MASQUE relay; gRPC datagrams are fixed-destination only"
    );
}

#[test]
fn relay_tcp_readiness_runtime_jsonl_e2e() {
    let td = TestDir::new("relay-tcp");
    let events_path = td.path().join("events.jsonl");
    let cfg_path = td.path().join("relay-tcp.toml");

    let socks_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "relay"

[ingress]
primary = "socks5"
allow_fallback = false

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false

[relay]
server = "127.0.0.1:8443"
server_name = "localhost"
auth_token = "{TEST_RELAY_AUTH_TOKEN}"
transport_priority = []
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    client
        .write_all(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x01\xbb")
        .expect("write connect request");
    let mut connect_resp = [0u8; 10];
    client
        .read_exact(&mut connect_resp)
        .expect("read connect response");
    assert_eq!(connect_resp[1], 1);
    drop(client);

    let (_record, records) = wait_for_event(
        &events_path,
        "ingress_tcp_connect_rejected",
        Duration::from_secs(10),
    );
    let codes = event_codes(&records);
    assert!(
        codes.contains(&"ingress_tcp_connect_rejected"),
        "{records:?}"
    );
    assert_no_event(&records, "ingress_session_failed");
    assert_no_event(&records, "ingress_session_broker_failed");
    assert_no_event(&records, "relay_transport_failed");

    let reject = records
        .iter()
        .find(|record| record["event_code"] == "ingress_tcp_connect_rejected")
        .expect("relay tcp reject event");
    assert_eq!(reject["fields"]["backend"], "socks5_fallback");
    assert_eq!(reject["fields"]["backend_kind"], "Socks5Fallback");
    assert_eq!(reject["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(reject["fields"]["requested_primary"], "Socks5");
    assert_eq!(reject["fields"]["requested_primary_code"], "socks5");
    assert_eq!(reject["fields"]["mode"], "Relay");
    assert_eq!(reject["fields"]["mode_code"], "relay");
    assert_eq!(reject["fields"]["wide_supported"], serde_json::Value::Null);
    assert_eq!(
        reject["fields"]["wide_platform_family_supported"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["wide_runtime_readiness"],
        serde_json::Value::Null
    );
    assert_eq!(reject["fields"]["rollout_profile"], serde_json::Value::Null);
    assert_eq!(
        reject["fields"]["rollout_profile_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["startup_path_code"],
        "socks5_fallback_started"
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(
        reject["fields"]["startup_bind_error_code"],
        serde_json::Value::Null
    );
    assert_eq!(reject["fields"]["request_kind"], "TcpConnect");
    assert_eq!(reject["fields"]["reject_stage"], "pre_broker_runtime_gate");
    assert_eq!(reject["fields"]["response_action"], "send_general_failure");
    assert_eq!(reject["fields"]["response_reply_code"], 1);
    assert_eq!(
        reject["fields"]["reject_reason_code"],
        "tcp_connect_requires_runtime_ready_relay_transport"
    );
    assert_eq!(
        reject["fields"]["reason"],
        "relay mode requires a runtime-ready relay transport"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn wide_bind_fallback_session_broker_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-bind-fallback-broker-failure");
    let events_path = td.path().join("wide-bind-fallback-broker-failure.jsonl");
    let cfg_path = td.path().join("wide-bind-fallback-broker-failure.toml");

    let wide_port = reserve_tcp_port();
    let socks_port = reserve_tcp_port();
    let _occupied = StdTcpListener::bind(("127.0.0.1", wide_port)).expect("occupy wide port");

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = true

[ingress.wide]
enabled = true
platform_backend = "auto"
listen = "127.0.0.1:{wide_port}"
capture_dns = false
default_mark = 0

[socks]
listen = "127.0.0.1:{socks_port}"

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let (fallback, _records) = wait_for_event(
        &events_path,
        "ingress_wide_bind_fallback",
        Duration::from_secs(10),
    );
    assert_eq!(fallback["fields"]["requested_primary"], "Wide");
    assert_eq!(fallback["fields"]["fallback_backend"], "socks5_fallback");
    assert_eq!(fallback["fields"]["bind_error_code"], "listener_busy");

    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "socks5_fallback");
    assert_eq!(started["fields"]["backend_kind_code"], "socks5_fallback");
    assert_eq!(started["fields"]["requested_primary_code"], "wide");
    assert_eq!(started["fields"]["mode_code"], "direct");
    assert_eq!(
        started["fields"]["startup_path_code"],
        "wide_bind_failed_fallback_started"
    );
    assert_eq!(
        started["fields"]["startup_bind_error_code"],
        "listener_busy"
    );
    assert_eq!(
        started["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_contract"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_support_tier"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_policy"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_runtime_scope"],
        serde_json::Value::Null
    );
    assert_eq!(started["fields"]["wide_dns_port"], serde_json::Value::Null);

    let mut client = wait_for_port(socks_port, Duration::from_secs(20));
    client.write_all(b"\x05\x01\x00").expect("write greeting");
    let mut greeting = [0u8; 2];
    client.read_exact(&mut greeting).expect("read greeting");
    assert_eq!(greeting, [0x05, 0x00]);
    let host = b"nonexistent.invalid";
    let mut request = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    request.extend_from_slice(host);
    request.extend_from_slice(&443u16.to_be_bytes());
    client.write_all(&request).expect("write connect request");
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).expect("read reply");
    assert_eq!(reply[1], 4);
    drop(client);

    let (broker_fail, _records) = wait_for_event(
        &events_path,
        "ingress_session_broker_failed",
        Duration::from_secs(10),
    );
    assert_eq!(broker_fail["fields"]["ingress_kind"], "Socks5Fallback");
    assert_eq!(
        broker_fail["fields"]["ingress_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["backend"], "socks5_fallback");
    assert_eq!(
        broker_fail["fields"]["backend_kind_code"],
        "socks5_fallback"
    );
    assert_eq!(broker_fail["fields"]["requested_primary"], "Wide");
    assert_eq!(broker_fail["fields"]["requested_primary_code"], "wide");
    assert_eq!(broker_fail["fields"]["mode"], "Direct");
    assert_eq!(broker_fail["fields"]["mode_code"], "direct");
    assert_eq!(broker_fail["fields"]["wide_supported"], true);
    assert_eq!(
        broker_fail["fields"]["wide_platform_family_supported"],
        true
    );
    assert_eq!(broker_fail["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(broker_fail["fields"]["rollout_profile"], "OutputOnlySafe");
    assert_eq!(
        broker_fail["fields"]["rollout_profile_code"],
        "output_only_safe"
    );
    assert_eq!(
        broker_fail["fields"]["startup_path_code"],
        "wide_bind_failed_fallback_started"
    );
    assert_eq!(
        broker_fail["fields"]["startup_bind_error_code"],
        "listener_busy"
    );
    assert_eq!(
        broker_fail["fields"]["startup_fallback_reason_code"],
        serde_json::Value::Null
    );
    assert_eq!(
        broker_fail["fields"]["startup_fallback_reason"],
        serde_json::Value::Null
    );
    assert_eq!(broker_fail["fields"]["broker_error_code"], "resolve_failed");
    assert_eq!(broker_fail["fields"]["request_kind"], "TcpConnect");
    assert_eq!(broker_fail["fields"]["broker_stage"], "resolve_target");
    assert_eq!(broker_fail["fields"]["target_host"], "nonexistent.invalid");
}

#[cfg(target_os = "linux")]
#[test]
fn wide_dns_preview_status_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-dns-preview-status");
    let events_path = td.path().join("wide-dns-preview-status.jsonl");
    let cfg_path = td.path().join("wide-dns-preview-status.toml");

    let wide_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "auto"
listen = "127.0.0.1:{wide_port}"
capture_dns = true
default_mark = 0

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);
    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "wide_primary");
    assert_eq!(
        started["fields"]["backend_runtime_id"],
        "wide_primary_linux"
    );
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(started["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(
        started["fields"]["wide_dns_capture_preview_status"],
        "active"
    );
    assert_eq!(
        started["fields"]["wide_dns_capture_preview_error_kind"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_dns_capture_preview_error"],
        serde_json::Value::Null
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_support_tier"],
        "supported_preview"
    );
    assert_eq!(started["fields"]["wide_dns_port"], 53);
}

#[cfg(target_os = "linux")]
#[test]
fn wide_original_destination_accept_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-accept-failed");
    let events_path = td.path().join("wide-accept-failed.jsonl");
    let cfg_path = td.path().join("wide-accept-failed.toml");

    let wide_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "auto"
listen = "127.0.0.1:{wide_port}"
capture_dns = true
default_mark = 0

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let first = wait_for_port(wide_port, Duration::from_secs(20));
    drop(first);

    let second = wait_for_port(wide_port, Duration::from_secs(20));
    drop(second);
    let (matches, records) =
        wait_for_wide_accept_outcome(&events_path, "wide_original_destination:", 2);

    if let Some(accept_fail) = matches.first() {
        assert_eq!(accept_fail["fields"]["backend"], "wide_primary");
        assert_eq!(
            accept_fail["fields"]["backend_runtime_id"],
            "wide_primary_linux"
        );
        assert_eq!(accept_fail["fields"]["backend_kind"], "WidePrimary");
        assert_eq!(accept_fail["fields"]["requested_primary"], "Wide");
        assert_eq!(accept_fail["fields"]["mode"], "Direct");
        assert_eq!(accept_fail["fields"]["wide_supported"], true);
        assert_eq!(
            accept_fail["fields"]["wide_platform_family_supported"],
            true
        );
        assert_eq!(accept_fail["fields"]["wide_runtime_readiness"], "ready");
        assert_eq!(accept_fail["fields"]["rollout_profile"], "OutputOnlySafe");
        // Linux kernels disagree on the exact errno surfaced by SO_ORIGINAL_DST
        // for loopback/self-connect lab traffic, so only require a structured
        // machine-readable error kind here.
        assert!(accept_fail["fields"]["accept_error_kind"]
            .as_str()
            .is_some());
        assert!(accept_fail["fields"]["error"]
            .as_str()
            .expect("wide accept error")
            .contains("wide_original_destination:"));
        return;
    }

    // Some Linux kernels report loopback connects through SO_ORIGINAL_DST as a
    // valid local destination instead of failing the accept path. In that case
    // the earlier unit-level backend test already validates the accepted target
    // shape, so this runtime e2e only needs to confirm the wide listener stays
    // up and does not surface an unrelated accept failure contract.
    assert!(
        !records.iter().any(|record| {
            record["event_code"] == "ingress_accept_failed"
                && !record["fields"]["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("wide_original_destination:")
        }),
        "unexpected ingress_accept_failed records: {records:?}"
    );
    let third = wait_for_port(wide_port, Duration::from_secs(10));
    drop(third);
}

#[cfg(target_os = "linux")]
#[test]
fn wide_dns_original_destination_accept_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-dns-accept-failed");
    let events_path = td.path().join("wide-dns-accept-failed.jsonl");
    let cfg_path = td.path().join("wide-dns-accept-failed.toml");

    let wide_port = reserve_tcp_port();
    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "auto"
listen = "127.0.0.1:{wide_port}"
capture_dns = true
default_mark = 0

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);
    let first = wait_for_port(wide_port, Duration::from_secs(20));
    drop(first);

    let udp = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp sender");
    udp.send_to(b"\xaa\xbb", ("127.0.0.1", wide_port))
        .expect("send first dns preview datagram");
    udp.send_to(b"\xcc\xdd", ("127.0.0.1", wide_port))
        .expect("send second dns preview datagram");

    let (matches, records) =
        wait_for_wide_accept_outcome(&events_path, "wide_dns_original_destination:", 2);
    if let Some(accept_fail) = matches.first() {
        assert_eq!(accept_fail["fields"]["backend"], "wide_primary");
        assert_eq!(
            accept_fail["fields"]["backend_runtime_id"],
            "wide_primary_linux"
        );
        assert_eq!(accept_fail["fields"]["backend_kind"], "WidePrimary");
        assert_eq!(accept_fail["fields"]["requested_primary"], "Wide");
        assert_eq!(accept_fail["fields"]["mode"], "Direct");
        assert_eq!(accept_fail["fields"]["wide_supported"], true);
        assert_eq!(
            accept_fail["fields"]["wide_platform_family_supported"],
            true
        );
        assert_eq!(accept_fail["fields"]["wide_runtime_readiness"], "ready");
        assert_eq!(accept_fail["fields"]["rollout_profile"], "OutputOnlySafe");
        assert!(accept_fail["fields"]["accept_error_kind"]
            .as_str()
            .is_some());
        assert!(accept_fail["fields"]["error"]
            .as_str()
            .expect("wide dns accept error")
            .contains("wide_dns_original_destination:"));

        // A failed UDP preview datagram must not poison the wide loop; the backend
        // should continue receiving later datagrams and surface the same contract.
        udp.send_to(b"\xee\xff", ("127.0.0.1", wide_port))
            .expect("send third dns preview datagram");
        let (matches_after_retry, _) =
            wait_for_wide_accept_outcome(&events_path, "wide_dns_original_destination:", 3);
        assert_eq!(matches_after_retry.len(), 3);
        return;
    }

    // Some Linux/container profiles do not expose a working best-effort
    // IP_RECVORIGDSTADDR preview socket at startup, in which case ordinary UDP
    // lab traffic simply does not enter the narrow DNS path. That should still
    // leave the wide backend healthy and must not surface unrelated accept
    // failure contracts.
    assert!(
        !records.iter().any(|record| {
            record["event_code"] == "ingress_accept_failed" && {
                let error = record["fields"]["error"].as_str().unwrap_or_default();
                !error.contains("wide_dns_original_destination:")
                    && !error.contains("wide_original_destination:")
            }
        }),
        "unexpected ingress_accept_failed records: {records:?}"
    );
    let third = wait_for_port(wide_port, Duration::from_secs(10));
    drop(third);
}

#[cfg(target_os = "linux")]
#[test]
fn wide_ipv6_original_destination_accept_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-ipv6-accept");
    let events_path = td.path().join("wide-ipv6-accept.jsonl");
    let cfg_path = td.path().join("wide-ipv6-accept.toml");

    let wide_listener = std::net::TcpListener::bind("[::1]:0").expect("bind v6 port");
    let wide_port = wide_listener.local_addr().expect("wide v6 addr").port();
    drop(wide_listener);

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "auto"
listen = "[::]:{wide_port}"
capture_dns = false
default_mark = 0

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);

    let first = wait_for_v6_port(wide_port, Duration::from_secs(20));
    drop(first);

    let second = wait_for_v6_port(wide_port, Duration::from_secs(20));
    drop(second);
    let (matches, records) =
        wait_for_wide_accept_outcome(&events_path, "wide_original_destination:", 2);

    if let Some(accept_fail) = matches.first() {
        assert_eq!(accept_fail["fields"]["backend"], "wide_primary");
        assert_eq!(
            accept_fail["fields"]["backend_runtime_id"],
            "wide_primary_linux"
        );
        assert_eq!(accept_fail["fields"]["backend_kind"], "WidePrimary");
        assert_eq!(accept_fail["fields"]["requested_primary"], "Wide");
        assert_eq!(accept_fail["fields"]["mode"], "Direct");
        assert_eq!(accept_fail["fields"]["wide_supported"], true);
        assert_eq!(
            accept_fail["fields"]["wide_platform_family_supported"],
            true
        );
        assert_eq!(accept_fail["fields"]["wide_runtime_readiness"], "ready");
        assert_eq!(accept_fail["fields"]["rollout_profile"], "OutputOnlySafe");
        assert!(accept_fail["fields"]["accept_error_kind"]
            .as_str()
            .is_some());
        assert!(accept_fail["fields"]["error"]
            .as_str()
            .expect("wide ipv6 accept error")
            .contains("wide_original_destination:"));
        return;
    }

    assert!(
        !records.iter().any(|record| {
            record["event_code"] == "ingress_accept_failed"
                && !record["fields"]["error"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("wide_original_destination:")
        }),
        "unexpected ingress_accept_failed records: {records:?}"
    );
    let third = wait_for_v6_port(wide_port, Duration::from_secs(10));
    drop(third);
}

#[cfg(target_os = "linux")]
#[test]
fn wide_ipv6_dns_original_destination_accept_failure_runtime_jsonl_e2e() {
    let td = TestDir::new("wide-ipv6-dns-accept-failed");
    let events_path = td.path().join("wide-ipv6-dns-accept-failed.jsonl");
    let cfg_path = td.path().join("wide-ipv6-dns-accept-failed.toml");

    let wide_listener = std::net::TcpListener::bind("[::1]:0").expect("bind v6 port");
    let wide_port = wide_listener.local_addr().expect("wide v6 addr").port();
    drop(wide_listener);

    // Own state file — never the operator's real ~/.cache/aegis/state.json,
    // which this client cannot decrypt and so refuses to start.
    let aegis_test_state = td.path().join("aegis-test-state.json");
    let aegis_test_state = aegis_test_state
        .to_string_lossy()
        .replace(char::from(92), "/");
    common::write_private_file(
        &cfg_path,
        format!(
            r#"mode = "direct"

[ingress]
primary = "wide"
allow_fallback = false

[ingress.wide]
enabled = true
platform_backend = "auto"
listen = "[::]:{wide_port}"
capture_dns = true
default_mark = 0

[direct]
state_path = "{aegis_test_state}"
strategies = ["passthrough"]
epsilon = 0.0
first_chunk_timeout_ms = 1000
freeze_threshold_bytes = 16384
degraded_latency_ms = 5000
tls_grease = false
sni_case_obfuscate = false
inject_opaque_extension = false
ghost_jitter_before_attempt = false
"#
        ),
    )
    .expect("write config");

    let _client = ChildGuard::spawn(&cfg_path, &events_path);
    let (started, _records) = wait_for_event(
        &events_path,
        "ingress_backend_started",
        Duration::from_secs(10),
    );
    assert_eq!(started["fields"]["backend"], "wide_primary");
    assert_eq!(
        started["fields"]["backend_runtime_id"],
        "wide_primary_linux"
    );
    assert_eq!(started["fields"]["requested_primary"], "Wide");
    assert_eq!(started["fields"]["wide_runtime_readiness"], "ready");
    assert_eq!(
        started["fields"]["wide_dns_capture_preview_status"],
        "active"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_runtime_scope"],
        "linux_ipv6_only"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_contract"],
        "preview_allowlist_only"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_support_tier"],
        "supported_preview"
    );
    assert_eq!(
        started["fields"]["wide_udp_capture_policy"],
        "allowlist_ports"
    );
    assert_eq!(started["fields"]["wide_dns_port"], 53);

    let first = wait_for_v6_port(wide_port, Duration::from_secs(20));
    drop(first);

    let udp = std::net::UdpSocket::bind("[::1]:0").expect("bind v6 udp sender");
    udp.send_to(b"\xaa\xbb", ("::1", wide_port))
        .expect("send first ipv6 dns preview datagram");
    udp.send_to(b"\xcc\xdd", ("::1", wide_port))
        .expect("send second ipv6 dns preview datagram");

    let (matches, records) =
        wait_for_wide_accept_outcome(&events_path, "wide_dns_original_destination:", 2);
    if let Some(accept_fail) = matches.first() {
        assert_eq!(accept_fail["fields"]["backend"], "wide_primary");
        assert_eq!(
            accept_fail["fields"]["backend_runtime_id"],
            "wide_primary_linux"
        );
        assert_eq!(accept_fail["fields"]["backend_kind"], "WidePrimary");
        assert_eq!(accept_fail["fields"]["requested_primary"], "Wide");
        assert_eq!(accept_fail["fields"]["mode"], "Direct");
        assert_eq!(accept_fail["fields"]["wide_supported"], true);
        assert_eq!(
            accept_fail["fields"]["wide_platform_family_supported"],
            true
        );
        assert_eq!(accept_fail["fields"]["wide_runtime_readiness"], "ready");
        assert_eq!(accept_fail["fields"]["rollout_profile"], "OutputOnlySafe");
        assert!(accept_fail["fields"]["accept_error_kind"]
            .as_str()
            .is_some());
        assert!(accept_fail["fields"]["error"]
            .as_str()
            .expect("wide ipv6 dns accept error")
            .contains("wide_dns_original_destination:"));

        udp.send_to(b"\xee\xff", ("::1", wide_port))
            .expect("send third ipv6 dns preview datagram");
        let (matches_after_retry, _) =
            wait_for_wide_accept_outcome(&events_path, "wide_dns_original_destination:", 3);
        assert_eq!(matches_after_retry.len(), 3);
        return;
    }

    assert!(
        !records.iter().any(|record| {
            record["event_code"] == "ingress_accept_failed" && {
                let error = record["fields"]["error"].as_str().unwrap_or_default();
                !error.contains("wide_dns_original_destination:")
                    && !error.contains("wide_original_destination:")
            }
        }),
        "unexpected ingress_accept_failed records: {records:?}"
    );
    let third = wait_for_v6_port(wide_port, Duration::from_secs(10));
    drop(third);
}
