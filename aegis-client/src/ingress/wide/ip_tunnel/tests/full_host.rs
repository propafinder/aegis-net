//! Explicit current-host gate. Uses only newly provisioned test relay credentials.
//! No reboot or user-file deletion. A prearmed independent child attempts
//! bounded owned recovery on parent loss. UNKNOWN never means restored; kernel
//! calls, runner termination and reboot are not covered by userland deadlines.
use super::owned_process::HeldCommand;
use super::*;
use aegis_core::{tunnel_policy::WindowsTunnelSettings, windows_file, windows_tunnel::firewall};
use std::{
    fs,
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

const TEST: &str = "ingress::wide::ip_tunnel::tests::full_host::current_host_full_tunnel";
const CAPTURE_BUDGET: Duration = Duration::from_secs(35);
const RECOVERY_TRIGGER: u64 = 60;
// Native SCM stop has distinct45s state and45s process waits. Uninstall adds
//45s deletion and60s mapped-file removal. These are accounted reserves, not a
// claim that killing winctl necessarily stopped its managed service.
const RECOVERY_BUDGET: Duration = Duration::from_secs(92);
const UNINSTALL_BUDGET: Duration = Duration::from_secs(197);

struct ControlScope {
    logs: PathBuf,
    deadline: Option<std::time::Instant>,
}

fn operation_observation<T, E>(
    outcome: &Result<Result<T, E>, tokio::time::error::Elapsed>,
    deadline: std::time::Instant,
) -> &'static str {
    match outcome {
        Err(_) => "TIMED_OUT",
        Ok(Err(_)) => "FAILED_PANIC",
        Ok(Ok(_)) if std::time::Instant::now() < deadline => "PASSED",
        // Tokio may return Ok after its future completes one synchronous poll
        // across the timer cutoff. The final caller observation is mandatory.
        Ok(Ok(_)) => "TIMED_OUT",
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoteFixture {
    address: SocketAddr,
    server_name: String,
    auth_token: String,
    ca_pem: String,
    tcp_port: u16,
    udp_port: u16,
    dns_upstream: SocketAddr,
    server_version: String,
    #[serde(default)]
    expected_egress_v4: Option<std::net::Ipv4Addr>,
}
fn control_result(
    exe: &Path,
    args: &[&str],
    scope: &ControlScope,
) -> std::io::Result<serde_json::Value> {
    let budget = if args.starts_with(&["client", "uninstall"]) {
        UNINSTALL_BUDGET
    } else {
        RECOVERY_BUDGET
    };
    let deadline = scope
        .deadline
        .unwrap_or_else(|| std::time::Instant::now() + budget);
    if std::time::Instant::now() >= deadline {
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "control phase expired before spawn",
        ));
    }
    let mut command = Command::new(exe);
    command
        .args(args)
        .creation_flags(0x08000000)
        .stdin(Stdio::null());
    let outcome = HeldCommand::spawn(&mut command, &scope.logs)?.finish(deadline);
    let decoded = serde_json::from_slice::<serde_json::Value>(&outcome.stdout);
    let control_ok = decoded.as_ref().is_ok_and(|value| value["ok"] == true);
    let receipt = serde_json::json!({
        "controller_outcome":outcome.reason,"exit_code":outcome.status.and_then(|s|s.code()),
        "pid":outcome.pid,"exact_child_kill_requested":outcome.killed,"child_reaped":outcome.reaped,
        "stdout":outcome.stdout_path,"stderr":outcome.stderr_path,
        "stdout_retained_prefix_bytes":outcome.stdout.len(),"stderr_retained_prefix_bytes":outcome.stderr.len(),
        "output_limit_exceeded":outcome.output_limit_exceeded,"output_read_failed":outcome.output_read_failed,
        "spool_custody_confirmed":outcome.spool_custody_confirmed,
        "control_json_valid":decoded.is_ok(),"control_ok":control_ok,"native_recovery_proven_by_controller_exit":false,
    });
    let record = outcome.stdout_path.with_extension("receipt.json");
    windows_file::write_private_new(&record, &serde_json::to_vec_pretty(&receipt)?, false)?;
    if !outcome.success() || !control_ok {
        return Err(std::io::Error::other(format!(
            "owned control FAILED/UNKNOWN; receipt {}",
            record.display()
        )));
    }
    decoded.map_err(std::io::Error::other)
}
fn control(exe: &Path, args: &[&str], scope: &ControlScope) -> serde_json::Value {
    control_result(exe, args, scope).unwrap()
}
struct Watchdog {
    child: HeldCommand,
    deadline: std::time::Instant,
    evidence: PathBuf,
}
impl Watchdog {
    fn confirm(self) -> std::io::Result<()> {
        let outcome = self.child.finish(self.deadline);
        if !outcome.success() {
            return Err(std::io::Error::other(
                "watchdog FAILED/UNKNOWN; no native restoration claim",
            ));
        }
        let receipt: serde_json::Value = serde_json::from_slice(&fs::read(self.evidence)?)?;
        if receipt["owned_disconnect_succeeded"] != true
            || receipt["baseline_restoration_confirmed"] != true
        {
            return Err(std::io::Error::other("watchdog restoration not confirmed"));
        }
        Ok(())
    }
}
fn watchdog(root: &Path, ctl: &Path, evidence: &Path, seconds: u64) -> Watchdog {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", TEST, "--ignored", "--nocapture"])
        .env("AEGIS_HOST_WATCHDOG_ROOT", root)
        .env("AEGIS_HOST_WATCHDOG_CTL", ctl)
        .env("AEGIS_HOST_WATCHDOG_EVIDENCE", evidence)
        .env("AEGIS_HOST_WATCHDOG_SECONDS", seconds.to_string())
        .creation_flags(0x08000000)
        .stdin(Stdio::null());
    let mut child = HeldCommand::spawn(&mut command, root.parent().unwrap()).unwrap();
    let ready = child.wait_ready_file(
        &evidence.with_extension("ready"),
        std::time::Instant::now() + Duration::from_secs(10),
    );
    if let Err(error) = ready {
        let outcome = child.finish(std::time::Instant::now());
        panic!(
            "watchdog did not arm: {error}; child_reaped={}",
            outcome.reaped
        );
    }
    child.preserve_on_parent_loss();
    Watchdog {
        child,
        deadline: std::time::Instant::now()
            + Duration::from_secs(seconds)
            + RECOVERY_BUDGET
            + Duration::from_secs(3),
        evidence: evidence.to_owned(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "explicit user consent for current-host global routes/DNS/WFP; requires AEGIS_ALLOW_MACHINE_WIDE_TEST=1 and candidate paths"]
async fn current_host_full_tunnel() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    assert_eq!(
        std::env::var("AEGIS_ALLOW_MACHINE_WIDE_TEST").as_deref(),
        Ok("1")
    );
    if let Some(root) = std::env::var_os("AEGIS_HOST_WATCHDOG_ROOT") {
        let root = PathBuf::from(root).canonicalize().unwrap();
        let parent = PathBuf::from(std::env::var_os("ProgramData").unwrap())
            .canonicalize()
            .unwrap();
        assert!(root.starts_with(&parent));
        assert!(root
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("AEGIS-Full-Host-Test-"));
        let evidence = PathBuf::from(std::env::var_os("AEGIS_HOST_WATCHDOG_EVIDENCE").unwrap());
        assert_eq!(
            evidence.parent().unwrap().canonicalize().unwrap(),
            root.parent().unwrap()
        );
        let ctl = PathBuf::from(std::env::var_os("AEGIS_HOST_WATCHDOG_CTL").unwrap());
        let seconds: u64 = std::env::var("AEGIS_HOST_WATCHDOG_SECONDS")
            .unwrap()
            .parse()
            .unwrap();
        assert!((1..=60).contains(&seconds));
        windows_file::write_private_new(&evidence.with_extension("ready"), b"armed", false)
            .unwrap();
        std::thread::sleep(Duration::from_secs(seconds));
        let scope = ControlScope {
            logs: root.parent().unwrap().to_owned(),
            deadline: None,
        };
        let result = control_result(
            &ctl,
            &["client", "disconnect", "--root", root.to_str().unwrap()],
            &scope,
        );
        let baseline =
            aegis_core::secret_file::read(&scope.logs.join("baseline-routes.json"), 65536)
                .and_then(|raw| {
                    serde_json::from_slice::<Vec<(u64, String, u32)>>(&raw)
                        .map_err(std::io::Error::other)
                });
        let restored = result.is_ok()
            && firewall::status().is_ok_and(|status| status == 0)
            && baseline.as_ref().is_ok_and(|expected| {
                aegis_core::windows_tunnel::network::default_route_signature(0)
                    .is_ok_and(|routes| routes == *expected)
            });
        let receipt = serde_json::json!({
            "owned_disconnect_succeeded":result.is_ok(),"baseline_restoration_confirmed":restored,
            "recovery_outcome":if restored {"CONFIRMED"} else {"FAILED_OR_UNKNOWN"},
            "controller_error":result.as_ref().err().map(|e|e.to_string()),
            "runner_loss_reboot_or_kernel_deadline_proven":false,
        });
        windows_file::write_private_new(
            &evidence,
            &serde_json::to_vec_pretty(&receipt).unwrap(),
            false,
        )
        .unwrap();
        assert!(
            restored,
            "independent bounded recovery FAILED/UNKNOWN; installation quarantined"
        );
        return;
    }
    let result_path = std::env::var_os("AEGIS_HOST_RESULT").map(PathBuf::from);
    if let Some(output) = &result_path {
        assert!(output.is_absolute() && !output.exists());
    }
    let inner_tls = match std::env::var("AEGIS_HOST_INNER_TLS").as_deref() {
        Err(_) | Ok("0") => false,
        Ok("1") => true,
        _ => panic!("AEGIS_HOST_INNER_TLS must be 0 or 1"),
    };
    assert!(
        !inner_tls || std::env::var_os("AEGIS_HOST_REMOTE_FIXTURE").is_none(),
        "inner TLS host acceptance uses only its own local synthetic identity"
    );
    assert_eq!(
        firewall::status().unwrap(),
        0,
        "existing product protection must be inactive"
    );
    let baseline = aegis_core::windows_tunnel::network::default_route_signature(0).unwrap();
    let ctl = PathBuf::from(std::env::var_os("AEGIS_TEST_WINCTL").unwrap());
    let kit = ctl.parent().unwrap();
    let manifest = fs::read(kit.join("manifest.json")).unwrap();
    use sha2::{Digest, Sha256};
    let pin = format!("{:x}", Sha256::digest(&manifest));
    let parent = PathBuf::from(std::env::var_os("ProgramData").unwrap())
        .join(format!("AEGIS-Full-Host-Test-{}", std::process::id()));
    assert!(!parent.exists());
    windows_file::create_private_directory(&parent, true, false).unwrap();
    windows_file::write_private_new(
        &parent.join("baseline-routes.json"),
        &serde_json::to_vec_pretty(&baseline).unwrap(),
        false,
    )
    .unwrap();
    let controls = ControlScope {
        logs: parent.clone(),
        deadline: None,
    };
    control(
        &ctl,
        &[
            "package",
            "verify",
            "--package",
            kit.to_str().unwrap(),
            "--manifest-sha256",
            &pin,
        ],
        &controls,
    );
    let root = parent.join("installation");
    let service = format!("AegisFullHostTest{}", std::process::id());
    assert_eq!(
        control(
            &ctl,
            &["service", "status", "--service-name", &service],
            &controls
        )["service"]["exists"],
        false
    );
    let (tcp, echo) = echo_tcp("127.0.0.1".parse().unwrap()).await;
    let (udp, udp_echo) = echo_udp("127.0.0.1".parse().unwrap()).await;
    // Select an existing local unicast address without transmitting a packet.
    // The production resolver validation intentionally rejects loopback.
    let selection = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    selection.connect("192.0.2.1:9").unwrap();
    let local_ip = selection.local_addr().unwrap().ip();
    drop(selection);
    let dns_socket = tokio::net::UdpSocket::bind((local_ip, 0)).await.unwrap();
    let dns_upstream = dns_socket.local_addr().unwrap();
    let dns_server = tokio::spawn(async move {
        let mut bytes = [0u8; 4096];
        loop {
            let (n, peer) = dns_socket.recv_from(&mut bytes).await.unwrap();
            if n < 12 {
                continue;
            }
            // Local NODATA response for non-A questions. The tunnel itself
            // answers A with fake IPs; no public DNS server or recursion.
            bytes[2] = 0x80 | (bytes[2] & 1);
            bytes[3] = 0x80;
            bytes[6..12].fill(0);
            dns_socket.send_to(&bytes[..n], peer).await.unwrap();
        }
    });
    // A local relay must never recursively capture background applications'
    // Internet traffic into itself. Only these local fixture ports are allowed.
    let ports = vec![tcp.port(), udp.port(), dns_upstream.port()];
    let (mut cfg, server) = if inner_tls {
        let identity = parent.join("synthetic-inner-tls");
        windows_file::create_private_directory(&identity, true, false).unwrap();
        let reservation = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = reservation.local_addr().unwrap().to_string();
        let (cfg, mut server_cfg) = crate::relay::secure_test_configs(&identity, &address);
        server_cfg.target_policy.allowed_ports = ports;
        server_cfg
            .transport
            .inner_tls
            .as_mut()
            .unwrap()
            .idle_timeout_ms = 30000;
        drop(reservation);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            aegis_server::run_server_with_ready(server_cfg, Some(ready_tx))
                .await
                .unwrap();
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        (cfg, server)
    } else {
        crate::tests::start_local_masque_server_for_ports(ports).await
    };
    let full = std::env::var("AEGIS_HOST_SCOPE").as_deref() != Ok("split");
    cfg.ingress.primary = aegis_core::IngressPrimary::Socks5;
    cfg.ingress.allow_fallback = false;
    let tcp_transport = match std::env::var("AEGIS_HOST_TCP_TRANSPORT").as_deref() {
        Err(_) | Ok("grpc_stream") => Family::GrpcStream,
        Ok("https_ws") => Family::HttpsWs,
        Ok("legacy_tls") => Family::LegacyTls,
        Ok("masque_derived") => Family::MasqueDerived,
        Ok(_) => panic!("unsupported test TCP transport"),
    };
    cfg.relay.transport_priority = vec![tcp_transport];
    assert!(!inner_tls || tcp_transport == Family::GrpcStream);
    cfg.relay.udp_transport_priority = Some(vec![Family::GrpcDatagram]);
    // Only a newly provisioned, explicitly selected test relay belongs here;
    // never discover or load the user's installed production profile.
    let remote: Option<RemoteFixture> = std::env::var_os("AEGIS_HOST_REMOTE_FIXTURE").map(|path| {
        serde_json::from_slice(&aegis_core::secret_file::read(Path::new(&path), 64 * 1024).unwrap())
            .unwrap()
    });
    let (tcp_port, udp_port, dns_upstream) = if let Some(remote) = &remote {
        assert!(!remote.address.ip().is_loopback());
        assert_ne!(remote.address.port(), 0);
        assert_ne!(remote.tcp_port, 0);
        assert_ne!(remote.udp_port, 0);
        let ca = parent.join("remote-test-ca.pem");
        windows_file::write_private_new(&ca, remote.ca_pem.as_bytes(), true).unwrap();
        cfg.relay.server = remote.address.to_string();
        cfg.relay.server_name = remote.server_name.clone();
        cfg.relay.auth_token = remote.auth_token.clone();
        cfg.relay.ca_cert = Some(ca);
        cfg.relay.masque_server =
            (tcp_transport == Family::MasqueDerived).then(|| remote.address.to_string());
        cfg.relay.masque_server_name =
            (tcp_transport == Family::MasqueDerived).then(|| remote.server_name.clone());
        (remote.tcp_port, remote.udp_port, remote.dns_upstream)
    } else {
        (tcp.port(), udp.port(), dns_upstream)
    };
    cfg.windows_tunnel = Some(WindowsTunnelSettings {
        adapter_name: format!("AEGIS-Full-Host-Test-{}", std::process::id()),
        dns_upstream,
        include_routes: if full {
            vec![]
        } else {
            vec![
                "198.18.0.0/16".into(),
                "198.19.255.2/32".into(),
                "fd00:ae61::2/128".into(),
            ]
        },
        configure_dns: full,
        kill_switch: full,
        ..Default::default()
    });
    let source = parent.join("synthetic-input.toml");
    windows_file::write_private_new(&source, toml::to_string(&cfg).unwrap().as_bytes(), true)
        .unwrap();
    control(
        &ctl,
        &[
            "client",
            "install",
            "--package",
            kit.to_str().unwrap(),
            "--manifest-sha256",
            &pin,
            "--config",
            source.to_str().unwrap(),
            "--root",
            root.to_str().unwrap(),
            "--service",
            "--service-name",
            &service,
        ],
        &controls,
    );
    struct Cleanup {
        record: PathBuf,
        completed: bool,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            if !self.completed {
                // No native command/wait in Drop. Active prearmed watchdog is
                // deliberately preserved on unwind; failed/unknown installation
                // is retained for disposable-host quarantine, never false green.
                let _ = windows_file::write_private_new(&self.record,
                    b"{\"cleanup_outcome\":\"FAILED_OR_UNKNOWN\",\"installation_quarantined\":true}", false);
            }
        }
    }
    let mut cleanup = Cleanup {
        record: parent.join("cleanup-unknown.json"),
        completed: false,
    };
    let dry_evidence = parent.join("watchdog-dry-run.json");
    watchdog(&root, &ctl, &dry_evidence, 1).confirm().unwrap();
    assert!(dry_evidence.exists());
    if std::env::var("AEGIS_HOST_PREPARE_ONLY").as_deref() == Ok("1") {
        control(
            &ctl,
            &["client", "uninstall", "--root", root.to_str().unwrap()],
            &controls,
        );
        cleanup.completed = true;
        drop(cleanup);
        server.abort();
        dns_server.abort();
        echo.abort();
        udp_echo.abort();
        eprintln!(
            "full host: recovery rehearsal passed without capture; evidence {}",
            parent.display()
        );
        return;
    }
    let evidence = parent.join("watchdog-restore.json");
    let restore = watchdog(&root, &ctl, &evidence, RECOVERY_TRIGGER);
    eprintln!("host test: watchdog verified and armed; starting capture (full={full}, TCP={tcp_transport:?})");
    let phase_deadline = std::time::Instant::now() + CAPTURE_BUDGET;
    let capture_controls = ControlScope {
        logs: parent.clone(),
        deadline: Some(phase_deadline),
    };
    let work = async {
        control(
            &ctl,
            &["client", "connect", "--root", root.to_str().unwrap()],
            &capture_controls,
        );
        let doctor = control(
            &ctl,
            &["client", "doctor", "--root", root.to_str().unwrap()],
            &capture_controls,
        );
        assert_eq!(doctor["tunnel"]["full_capture"], full);
        assert_eq!(
            doctor["tunnel"]["protection"]["live_interface_permits"],
            if full { 4 } else { 0 }
        );
        fs::write(
            parent.join("running-doctor.json"),
            serde_json::to_vec_pretty(&doctor).unwrap(),
        )
        .unwrap();
        assert_ne!(
            std::env::var("AEGIS_HOST_INJECT_FAILURE").as_deref(),
            Ok("1"),
            "intentional acceptance-harness failure after capture activation"
        );
        let request = dns_question("127.0.0.1");
        eprintln!("full host: direct UDP DNS query");
        let dns = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        dns.send_to(&request, (ANCHOR_V4, 53)).await.unwrap();
        let mut b = [0; 1500];
        let n = dns.recv(&mut b).await.unwrap();
        assert_eq!(b[3] & 15, 0);
        let fake = std::net::Ipv4Addr::new(b[n - 4], b[n - 3], b[n - 2], b[n - 1]);
        assert_eq!(fake.octets()[..2], [198, 18]);
        if full {
            let system_name = format!("aegis-full-{}.invalid:443", std::process::id());
            eprintln!("full host: Windows system DNS query");
            let resolved =
                tokio::time::timeout(Duration::from_secs(8), tokio::net::lookup_host(system_name))
                    .await
                    .unwrap()
                    .unwrap()
                    .collect::<Vec<_>>();
            assert!(
                resolved.iter().any(
                    |address| matches!(address.ip(), IpAddr::V4(ip) if ip.octets()[..2] == [198,18])
                ),
                "Windows system resolver did not use tunnel fake-IP DNS"
            );
        }
        let mut dns6 = tokio::net::TcpStream::connect((ANCHOR_V6, 53))
            .await
            .unwrap();
        dns6.write_u16(request.len() as u16).await.unwrap();
        dns6.write_all(&request).await.unwrap();
        let size = dns6.read_u16().await.unwrap();
        let mut response = vec![0; size as usize];
        dns6.read_exact(&mut response).await.unwrap();
        assert_eq!(response[3] & 15, 0);
        eprintln!("full host: TCP 2 MiB echo");
        let mut stream = tokio::net::TcpStream::connect((fake, tcp_port))
            .await
            .unwrap();
        let data = payload();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut echoed = vec![];
        stream.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed.len(), data.len(), "TCP response length changed");
        assert!(echoed == data, "TCP response content changed");
        eprintln!("full host: UDP 65000-byte echo");
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let data = vec![0x5a; 65000];
        socket.send_to(&data, (fake, udp_port)).await.unwrap();
        let mut echoed = vec![0; 65535];
        let n = socket.recv(&mut echoed).await.unwrap();
        assert_eq!(n, data.len(), "UDP response length changed");
        assert!(echoed[..n] == data, "UDP response content changed");
        let mut external_egress = false;
        if let Some(expected) = remote.as_ref().and_then(|r| r.expected_egress_v4) {
            assert!(!expected.is_loopback() && !expected.is_unspecified());
            eprintln!("full host: independently measured remote Internet egress");
            let curl =
                PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32/curl.exe");
            let mut command = Command::new(curl);
            command
                .args([
                    "--disable",
                    "--noproxy",
                    "*",
                    "-4",
                    "--fail",
                    "--silent",
                    "--show-error",
                    "--connect-timeout",
                    "8",
                    "--max-time",
                    "12",
                    "--max-filesize",
                    "64",
                    "https://api.ipify.org",
                ])
                .env_remove("SSLKEYLOGFILE")
                .creation_flags(0x08000000)
                .stdin(Stdio::null());
            let response = HeldCommand::spawn(&mut command, &parent)
                .unwrap()
                .finish(phase_deadline.min(std::time::Instant::now() + Duration::from_secs(12)));
            fs::write(
                parent.join("https-egress-probe.json"),
                serde_json::to_vec_pretty(&serde_json::json!({
                    "exit_code":response.status.and_then(|status|status.code()),
                    "controller_outcome":response.reason,"child_reaped":response.reaped,
                    "spool_custody_confirmed":response.spool_custody_confirmed,
                    "stderr":String::from_utf8_lossy(&response.stderr),
                    "stdout":String::from_utf8_lossy(&response.stdout),
                }))
                .unwrap(),
            )
            .unwrap();
            assert!(response.success(), "strict HTTPS egress probe failed");
            let actual: std::net::Ipv4Addr = std::str::from_utf8(&response.stdout)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            assert_eq!(actual, expected, "HTTPS escaped through a different egress");
            external_egress = true;
        }
        eprintln!("full host: stop and verify global fail-closed");
        control(
            &ctl,
            &["service", "stop", "--service-name", &service],
            &capture_controls,
        );
        let state = firewall::inspect(Some(&root.join("bin/aegis-client.exe"))).unwrap();
        assert_eq!(state.live_interface_permits, 0);
        if full {
            assert_eq!(state.persistent_blocks, 2);
            assert_eq!(state.boot_blocks, 2);
            // A hosted runner may have no physical IPv6 route after the real
            // tunnel disappears. WSAENETUNREACH is not firewall evidence.
            // Give both TEST-NET probes a valid, isolated route on a separate
            // adapter with no live WFP permit. No canary can reach the Internet.
            let canary = Wintun::open(
                &kit.join("wintun.dll"),
                &format!("AEGIS-Block-Probe-{}", std::process::id()),
            )
            .unwrap();
            let mut canary_network = NetworkGuard::configure(canary.luid, 1280, false).unwrap();
            for prefix in ["192.0.2.123/32", "2001:db8::123/128"] {
                canary_network
                    .capture(Prefix::parse(prefix).unwrap())
                    .unwrap();
            }
            for target in ["192.0.2.123:443", "[2001:db8::123]:443"] {
                let target: SocketAddr = target.parse().unwrap();
                assert_eq!(
                    aegis_core::windows_tunnel::network::native_route(target.ip())
                        .unwrap()
                        .luid,
                    canary.luid,
                    "fail-closed probe must have its own valid route: {target}"
                );
                let remaining = phase_deadline.saturating_duration_since(std::time::Instant::now());
                assert!(!remaining.is_zero(), "capture phase expired before canary");
                let error = std::net::TcpStream::connect_timeout(
                    &target,
                    remaining.min(Duration::from_secs(2)),
                )
                .unwrap_err();
                assert_eq!(
                    error.raw_os_error(),
                    Some(10013),
                    "WFP did not deny {target}"
                );
            }
            canary_network.cleanup().unwrap();
            drop(canary_network);
            drop(canary);
        }
        serde_json::json!({"tcp_2mib":true,"udp_65000":true,"udp_dns_v4":true,"tcp_dns_v6":true,
            "package_manifest_sha256":pin,
            "inner_tls":inner_tls,
            "full_capture":full,"windows_system_resolver":full,"global_fail_closed_after_stop_v4_v6":full,
            "fail_closed_probe_routes":if full {"isolated_test_net_adapter_without_permit"} else {"not_tested"},
            "relay":if remote.is_some() {"remote_synthetic"} else {"local_synthetic"},
            "remote_relay_payload_verified":remote.is_some(),
            "remote_server_version":remote.as_ref().map(|r| &r.server_version),
            "tcp_transport":tcp_transport,"udp_transport":Family::GrpcDatagram,
            "reboot_performed":false,"external_relay_egress_verified":external_egress,
            "expected_egress_v4":remote.as_ref().and_then(|r| r.expected_egress_v4)})
    };
    use futures::FutureExt;
    // Preserve the installation until both recovery paths have finished even
    // when a payload assertion panics. Report the original failure afterward.
    let outcome = tokio::time::timeout_at(
        tokio::time::Instant::from_std(phase_deadline),
        std::panic::AssertUnwindSafe(work).catch_unwind(),
    )
    .await;
    // Persist original operation failure BEFORE any cleanup call can fail or
    // panic. Later restoration cannot upgrade a failed operation to success.
    let operation_outcome = operation_observation(&outcome, phase_deadline);
    windows_file::write_private_new(
        &parent.join("operation-outcome.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({"operation_outcome":operation_outcome,
            "cleanup_outcome":"NOT_YET_CONFIRMED","capture_budget_seconds":35,
            "recovery_trigger_seconds":60,"kernel_deadline_proven":false}))
        .unwrap(),
        false,
    )
    .unwrap();
    // Restore immediately on completion/timeout. Independent watchdog is kept
    // alive until it has independently executed the same idempotent recovery.
    control(
        &ctl,
        &["client", "disconnect", "--root", root.to_str().unwrap()],
        &controls,
    );
    assert_eq!(firewall::status().unwrap(), 0);
    assert_eq!(
        aegis_core::windows_tunnel::network::default_route_signature(0).unwrap(),
        baseline
    );
    eprintln!(
        "full host: ordinary networking restored; waiting for independent recovery confirmation"
    );
    restore.confirm().unwrap();
    assert!(evidence.exists());
    // Keep the installed owner unchanged until independent restoration and
    // terminal child confirmation. Never race uninstall against the watchdog.
    assert_eq!(firewall::status().unwrap(), 0);
    assert_eq!(
        aegis_core::windows_tunnel::network::default_route_signature(0).unwrap(),
        baseline
    );
    windows_file::write_private_new(&parent.join("restoration-confirmed.json"),
        b"{\"parent_restore_confirmed\":true,\"independent_restore_confirmed\":true,\"watchdog_terminal\":true,\"uninstall_not_yet_confirmed\":true}", false).unwrap();
    control(
        &ctl,
        &["client", "uninstall", "--root", root.to_str().unwrap()],
        &controls,
    );
    cleanup.completed = true;
    drop(cleanup);
    server.abort();
    dns_server.abort();
    echo.abort();
    udp_echo.abort();
    let result = match outcome.unwrap() {
        Ok(result) if operation_outcome == "PASSED" => result,
        Ok(_) => panic!("completed capture work observed after deadline; no result admission"),
        Err(panic) => std::panic::resume_unwind(panic),
    };
    fs::write(
        parent.join("result.json"),
        serde_json::to_vec_pretty(&result).unwrap(),
    )
    .unwrap();
    if let Some(output) = result_path {
        windows_file::write_private_new(
            &output,
            &serde_json::to_vec_pretty(&result).unwrap(),
            false,
        )
        .unwrap();
    }
    eprintln!("full host evidence: {}", parent.display());
}

#[cfg(test)]
mod tests {
    use super::operation_observation;
    use std::time::{Duration, Instant};

    #[tokio::test(flavor = "current_thread")]
    async fn actual_single_synchronous_poll_completes_late_but_caller_refuses() {
        let deadline = Instant::now() + Duration::from_millis(20);
        let outcome = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            // Real synchronous work occupies a single poll past the timer.
            // No VM, network, service, policy or Windows privilege is used.
            while Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            Ok::<_, ()>("completed ordinary work")
        })
        .await;
        assert!(
            outcome.is_ok(),
            "fixture must demonstrate Tokio's late Ok completion"
        );
        assert!(Instant::now() >= deadline);
        assert_eq!(operation_observation(&outcome, deadline), "TIMED_OUT");
        // Production saves this disposition before cleanup and requires PASSED
        // for publication; late success cannot be upgraded by later restoration.
    }

    #[tokio::test(flavor = "current_thread")]
    async fn actual_timely_single_poll_completion_remains_passed() {
        let deadline = Instant::now() + Duration::from_secs(1);
        let outcome = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), async {
            Ok::<_, ()>("completed ordinary work")
        })
        .await;
        assert_eq!(operation_observation(&outcome, deadline), "PASSED");
    }
}
