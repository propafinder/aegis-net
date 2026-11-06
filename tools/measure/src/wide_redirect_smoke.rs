use std::{
    fs,
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs, UdpSocket},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

use serde_json::Value;
use socket2::{Domain, Protocol, Socket, Type};

pub struct WideRedirectPreflightExitInputs<'a> {
    pub preflight_json: &'a Path,
    pub preflight_log: &'a Path,
    pub status: i32,
    pub exit_listener_conflict: i32,
    pub exit_listener_busy: i32,
    pub exit_unsupported_adapter: i32,
    pub exit_socks_bind_failed: i32,
    pub exit_rollout_prerequisites: i32,
    pub expected_interface: &'a str,
}

pub fn reserve_tcp_port() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    println!("{}", listener.local_addr()?.port());
    Ok(())
}

pub fn wait_tcp_port(
    host: &str,
    port: u16,
    timeout_secs: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
    let addrs = (host, port).to_socket_addrs()?.collect::<Vec<_>>();
    while Instant::now() < deadline {
        for addr in &addrs {
            if TcpStream::connect_timeout(addr, Duration::from_millis(500)).is_ok() {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Err(format!("timed out waiting for {host}:{port}").into())
}

pub fn run_with_timeout(
    command: &[String],
    timeout_secs: f64,
) -> Result<i32, Box<dyn std::error::Error>> {
    let Some((program, args)) = command.split_first() else {
        return Err("run-with-timeout requires a command".into());
    };
    let mut child = Command::new(program).args(args).spawn()?;
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_secs);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status.code().unwrap_or(1));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Ok(124);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub fn validate_relay_transport_priority(priority: &str) -> Result<(), Box<dyn std::error::Error>> {
    let allowed = ["https_ws", "grpc_stream", "legacy_tls", "masque_derived"];
    let items = priority
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if items.is_empty() {
        return Err("relay transport priority must contain at least one transport".into());
    }
    let unknown = items
        .iter()
        .copied()
        .filter(|item| !allowed.contains(item))
        .collect::<Vec<_>>();
    if !unknown.is_empty() {
        return Err(format!("unknown relay transport(s): {}", unknown.join(", ")).into());
    }
    Ok(())
}

pub fn concat_text_files(
    inputs: &[std::path::PathBuf],
    output: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut combined = String::new();
    for input in inputs {
        let mut text = fs::read_to_string(input)?;
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        combined.push_str(&text);
    }
    fs::write(output, combined)?;
    Ok(())
}

pub fn warn_runtime_event_presence(
    runtime_events: &Path,
    event_code: &str,
    field_bool: Option<&str>,
    empty_warning: &str,
    missing_warning: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(runtime_events).unwrap_or_default();
    if raw.trim().is_empty() {
        eprintln!("{empty_warning}");
        return Ok(());
    }
    let found = raw.lines().filter_map(parse_json_line).any(|record| {
        if record.get("event_code").and_then(Value::as_str) != Some(event_code) {
            return false;
        }
        match field_bool {
            Some(field) => {
                record
                    .get("fields")
                    .and_then(|fields| fields.get(field))
                    .and_then(Value::as_bool)
                    == Some(true)
            }
            None => true,
        }
    });
    if !found {
        eprintln!("{missing_warning}");
    }
    Ok(())
}

fn parse_json_line(line: &str) -> Option<Value> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    serde_json::from_str(line).ok()
}

pub fn socks_http_probe(
    socks_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = connect_retry(("127.0.0.1", socks_port), 5)?;
    stream.write_all(&[0x05, 0x01, 0x00])?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting)?;
    if greeting != [0x05, 0x00] {
        return Err(format!("unexpected socks5 greeting response: {greeting:?}").into());
    }

    let target_ip: Ipv4Addr = target_host.parse()?;
    let mut connect = vec![0x05, 0x01, 0x00, 0x01];
    connect.extend_from_slice(&target_ip.octets());
    connect.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&connect)?;
    let mut response = [0_u8; 10];
    stream.read_exact(&mut response)?;
    if response[1] != 0x00 {
        return Err(format!("unexpected socks5 connect response: {response:?}").into());
    }

    let request = format!(
        "GET / HTTP/1.0\r\nHost: {target_host}:{target_port}\r\nUser-Agent: aegis-live-audit-relay\r\n\r\n"
    );
    stream.write_all(request.as_bytes())?;
    let mut payload = [0_u8; 256];
    let len = stream.read(&mut payload)?;
    if len == 0 {
        return Err("expected payload from relay target".into());
    }
    Ok(())
}

fn connect_retry(
    target: (&str, u16),
    attempts: usize,
) -> Result<TcpStream, Box<dyn std::error::Error>> {
    let mut last_error = None;
    for _ in 0..attempts {
        match TcpStream::connect_timeout(
            &SocketAddr::new(target.0.parse::<IpAddr>()?, target.1),
            Duration::from_secs(2),
        ) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                last_error = Some(err);
                std::thread::sleep(Duration::from_secs(1));
            }
        }
    }
    Err(last_error
        .map(|err| format!("transient relay socks listener did not accept connections: {err}"))
        .unwrap_or_else(|| "transient relay socks listener did not accept connections".to_owned())
        .into())
}

pub fn udp_echo_server(
    host: &str,
    port: u16,
    reuse_addr: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let addr = resolve_udp_addr(host, port)?;
    let socket = Socket::new(
        if addr.is_ipv6() {
            Domain::IPV6
        } else {
            Domain::IPV4
        },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if reuse_addr {
        socket.set_reuse_address(true)?;
    }
    socket.bind(&addr.into())?;
    let socket: UdpSocket = socket.into();
    let mut buffer = [0_u8; 4096];
    loop {
        let (len, peer) = socket.recv_from(&mut buffer)?;
        socket.send_to(&buffer[..len], peer)?;
    }
}

pub fn udp_echo_client(
    host: &str,
    port: u16,
    payload: &str,
    timeout_secs: f64,
) -> Result<(), Box<dyn std::error::Error>> {
    let target = resolve_udp_addr(host, port)?;
    let bind_addr = if target.is_ipv6() {
        SocketAddr::new(IpAddr::from([0_u16; 8]), 0)
    } else {
        SocketAddr::new(IpAddr::from([0_u8; 4]), 0)
    };
    let mut expected = vec![0xaa, 0xbb];
    expected.extend_from_slice(payload.as_bytes());
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(Duration::from_secs_f64(timeout_secs)))?;
    socket.set_write_timeout(Some(Duration::from_secs_f64(timeout_secs)))?;
    socket.send_to(&expected, target)?;
    let mut buffer = [0_u8; 4096];
    let (len, _) = socket.recv_from(&mut buffer)?;
    if buffer[..len] != expected {
        return Err(format!("unexpected_udp_echo: {:?}", &buffer[..len]).into());
    }
    Ok(())
}

fn resolve_udp_addr(host: &str, port: u16) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| format!("failed to resolve UDP target {host}:{port}").into())
}

pub fn wide_redirect_preflight_exit(
    inputs: WideRedirectPreflightExitInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let report = load_report(inputs.preflight_json, inputs.preflight_log)?;
    let selection = report.get("selection").unwrap_or(&Value::Null);
    let checks = report
        .get("runtime_checks")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let codes = checks
        .iter()
        .filter_map(|check| check.get("code").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let backend_notes = selection
        .get("backend_notes")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|note| note.get("code").and_then(Value::as_str))
        .collect::<Vec<_>>();
    let configured_interface = selection
        .get("wide_prerouting_interface")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let selection_error_code = selection
        .get("selection_error_code")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let platform_family_supported = selection
        .get("wide_platform_family_supported")
        .and_then(Value::as_bool)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string());
    let runtime_readiness = selection
        .get("wide_runtime_readiness")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let selected_backend = selection
        .get("selected_backend")
        .and_then(Value::as_str)
        .unwrap_or_default();

    println!(
        "Preflight backend={selected_backend} family_supported={platform_family_supported} readiness={runtime_readiness} codes={}",
        codes.join(",")
    );
    if !backend_notes.is_empty() {
        println!("Preflight backend_notes={}", backend_notes.join(","));
    }
    if !configured_interface.is_empty() {
        println!("Preflight prerouting_interface={configured_interface}");
    }

    let mapped = if inputs.status == 0 {
        if !inputs.expected_interface.is_empty()
            && configured_interface != inputs.expected_interface
        {
            eprintln!("Preflight failed: config/helper prerouting interface scope mismatch");
            eprintln!(
                "Remediation: keep ingress.wide.prerouting_interface ({configured_interface:?}) aligned with AEGIS_WIDE_INTERFACE ({:?})",
                inputs.expected_interface
            );
            inputs.exit_rollout_prerequisites
        } else {
            0
        }
    } else if runtime_readiness == "config_error"
        || selection_error_code == "rollout_profile_prerequisites"
    {
        eprintln!("Preflight failed: rollout profile prerequisites are not satisfied");
        eprintln!(
            "Remediation: for PREROUTING redirect smoke set AEGIS_ENABLE_PREROUTING=1 together with AEGIS_WIDE_INTERFACE=<iface>"
        );
        inputs.exit_rollout_prerequisites
    } else if runtime_readiness == "unsupported_adapter" {
        eprintln!("Preflight failed: selected wide backend has no supported runtime adapter here");
        eprintln!(
            "Remediation: keep redirect smoke on a Linux host with redirect-capable runtime support, or fall back to SOCKS5 diagnostics on unsupported platforms"
        );
        inputs.exit_unsupported_adapter
    } else if codes.contains(&"listener_conflict") {
        eprintln!("Preflight failed: wide.listen conflicts with socks.listen");
        eprintln!("Remediation: choose different AEGIS_WIDE_PORT and AEGIS_SOCKS_PORT values");
        inputs.exit_listener_conflict
    } else if codes.contains(&"listener_busy") {
        eprintln!("Preflight failed: requested wide.listen is already busy");
        eprintln!("Remediation: free the requested wide port or set a different AEGIS_WIDE_PORT");
        inputs.exit_listener_busy
    } else if codes.contains(&"socks_bind_failed") {
        eprintln!("Preflight failed: SOCKS5 fallback listener could not bind");
        eprintln!("Remediation: choose a different AEGIS_SOCKS_PORT");
        inputs.exit_socks_bind_failed
    } else {
        eprintln!("Preflight failed; inspect JSON report for details");
        inputs.status
    };
    std::process::exit(mapped);
}

fn load_report(
    stdout_path: &Path,
    stderr_path: &Path,
) -> Result<Value, Box<dyn std::error::Error>> {
    let stdout = fs::read_to_string(stdout_path).unwrap_or_default();
    let stderr = fs::read_to_string(stderr_path).unwrap_or_default();
    for stream in [&stdout, &stderr, &format!("{stdout}\n{stderr}")] {
        let payload = stream.trim();
        if payload.is_empty() {
            continue;
        }
        let Some(start) = payload.find('{') else {
            continue;
        };
        let Some(end) = payload.rfind('}') else {
            continue;
        };
        if end <= start {
            continue;
        }
        if let Ok(value) = serde_json::from_str(&payload[start..=end]) {
            return Ok(value);
        }
    }
    Err(format!("missing_json_report stdout={stdout:?} stderr={stderr:?}").into())
}
