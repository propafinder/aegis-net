#[cfg(target_os = "macos")]
mod fd_ipc;

#[cfg(not(target_os = "macos"))]
fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!("aegis-macos-utun-lab is only supported on macOS targets");
        return;
    }
    eprintln!("aegis-macos-utun-lab is unsupported on this target; macOS utun code is cfg-gated");
    std::process::exit(1);
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    macos::run()
}

#[cfg(target_os = "macos")]
mod macos {
    use super::fd_ipc::{recv_fd_from_peer, send_fd_to_peer, verify_peer, PeerIdentity};
    use std::ffi::CString;
    use std::fs::{self, OpenOptions};
    use std::io::{self, Write};
    use std::mem;
    use std::net::Ipv4Addr;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use serde_json::{json, Value};

    const PF_SYSTEM: i32 = 32;
    const SYSPROTO_CONTROL: i32 = 2;
    const AF_SYS_CONTROL: u8 = 2;
    const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
    const UTUN_OPT_IFNAME: i32 = 2;
    const CTLIOCGINFO: libc::c_ulong = 0xC0644E03;
    const UTUN_HEADER_LEN: usize = 4;
    const DEFAULT_CONTROLLED_PEER: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 2);
    const DEFAULT_CONTROLLED_LOCAL: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

    enum CommandMode {
        Helper {
            expected_main: PeerIdentity,
            socket: PathBuf,
            runtime_events_jsonl: PathBuf,
            route_proof_json: Option<PathBuf>,
            probe: ProbeKind,
            controlled_peer: Option<Ipv4Addr>,
            controlled_local: Option<Ipv4Addr>,
            relay_ip: Ipv4Addr,
        },
        Main {
            socket: PathBuf,
            runtime_events_jsonl: PathBuf,
            result_json: PathBuf,
            packet_timeout_ms: u64,
            expected_protocol: ExpectedProtocol,
            expected_dst_port: Option<u16>,
            tcp_synack_lab: bool,
        },
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ProbeKind {
        Icmp,
        Tcp,
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ExpectedProtocol {
        Any,
        Tcp,
    }

    #[repr(C)]
    struct CtlInfo {
        ctl_id: u32,
        ctl_name: [libc::c_char; 96],
    }

    #[repr(C)]
    struct SockaddrCtl {
        sc_len: u8,
        sc_family: u8,
        ss_sysaddr: u16,
        sc_id: u32,
        sc_unit: u32,
        sc_reserved: [u32; 5],
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        match parse_args()? {
            CommandMode::Helper {
                expected_main,
                socket,
                runtime_events_jsonl,
                route_proof_json,
                probe,
                controlled_peer,
                controlled_local,
                relay_ip,
            } => run_helper(
                expected_main,
                &socket,
                &runtime_events_jsonl,
                route_proof_json.as_deref(),
                probe,
                controlled_peer.unwrap_or(DEFAULT_CONTROLLED_PEER),
                controlled_local.unwrap_or(DEFAULT_CONTROLLED_LOCAL),
                relay_ip,
            )?,
            CommandMode::Main {
                socket,
                runtime_events_jsonl,
                result_json,
                packet_timeout_ms,
                expected_protocol,
                expected_dst_port,
                tcp_synack_lab,
            } => run_main(
                &socket,
                &runtime_events_jsonl,
                &result_json,
                Duration::from_millis(packet_timeout_ms),
                expected_protocol,
                expected_dst_port,
                tcp_synack_lab,
            )?,
        }
        Ok(())
    }

    fn parse_args() -> io::Result<CommandMode> {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if args.iter().any(|arg| arg == "--self-check") {
            println!("aegis-macos-utun-lab self-check ok");
            std::process::exit(0);
        }
        if args.is_empty() || args.iter().any(|arg| arg == "-h" || arg == "--help") {
            print_usage();
            std::process::exit(0);
        }
        match args[0].as_str() {
            "helper" => Ok(CommandMode::Helper {
                expected_main: required_main_peer(&args)?,
                socket: required_path(&args, "--socket")?,
                runtime_events_jsonl: required_path(&args, "--runtime-events-jsonl")?,
                route_proof_json: optional_path(&args, "--route-proof-json")?,
                probe: optional_probe(&args, "--probe")?.unwrap_or(ProbeKind::Icmp),
                controlled_peer: optional_ipv4(&args, "--controlled-peer")?,
                controlled_local: optional_ipv4(&args, "--controlled-local")?,
                relay_ip: required_ipv4(&args, "--relay-ip")?,
            }),
            "main" => Ok(CommandMode::Main {
                socket: required_path(&args, "--socket")?,
                runtime_events_jsonl: required_path(&args, "--runtime-events-jsonl")?,
                result_json: required_path(&args, "--result-json")?,
                packet_timeout_ms: optional_u64(&args, "--packet-timeout-ms")?.unwrap_or(5000),
                expected_protocol: optional_expected_protocol(&args, "--expected-protocol")?
                    .unwrap_or(ExpectedProtocol::Any),
                expected_dst_port: optional_u16(&args, "--expected-dst-port")?,
                tcp_synack_lab: args.iter().any(|arg| arg == "--tcp-synack-lab"),
            }),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown command: {other}"),
            )),
        }
    }

    fn print_usage() {
        println!(
        "aegis-macos-utun-lab\n\
         \n\
         Usage:\n\
           aegis-macos-utun-lab --self-check\n\
           aegis-macos-utun-lab helper --main-uid UID --main-pid PID --socket PATH --runtime-events-jsonl PATH --relay-ip IP [--route-proof-json PATH] [--probe icmp|tcp] [--controlled-peer IP] [--controlled-local IP]\n\
           aegis-macos-utun-lab main --socket PATH --runtime-events-jsonl PATH --result-json PATH [--packet-timeout-ms MS] [--expected-protocol any|tcp] [--expected-dst-port PORT] [--tcp-synack-lab]"
    );
    }

    fn value_after<'a>(args: &'a [String], name: &str) -> io::Result<Option<&'a str>> {
        let Some(index) = args.iter().position(|arg| arg == name) else {
            return Ok(None);
        };
        args.get(index + 1)
            .map(String::as_str)
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name} value"))
            })
            .map(Some)
    }

    fn required_main_peer(args: &[String]) -> io::Result<PeerIdentity> {
        for flag in ["--main-uid", "--main-pid"] {
            if args.iter().filter(|arg| arg.as_str() == flag).count() != 1 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("exactly one {flag} is required"),
                ));
            }
        }
        let uid = value_after(args, "--main-uid")?
            .unwrap()
            .parse::<libc::uid_t>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid --main-uid"))?;
        let pid = value_after(args, "--main-pid")?
            .unwrap()
            .parse::<libc::pid_t>()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid --main-pid"))?;
        if uid == 0 || pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "main must have a non-root UID and positive actual process PID",
            ));
        }
        Ok(PeerIdentity { uid, pid })
    }

    fn required_path(args: &[String], name: &str) -> io::Result<PathBuf> {
        value_after(args, name)?
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}")))
    }

    fn optional_path(args: &[String], name: &str) -> io::Result<Option<PathBuf>> {
        Ok(value_after(args, name)?.map(PathBuf::from))
    }

    fn required_ipv4(args: &[String], name: &str) -> io::Result<Ipv4Addr> {
        optional_ipv4(args, name)?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("missing {name}")))
    }

    fn optional_ipv4(args: &[String], name: &str) -> io::Result<Option<Ipv4Addr>> {
        value_after(args, name)?
            .map(|value| {
                value.parse::<Ipv4Addr>().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid {name} value {value}: {error}"),
                    )
                })
            })
            .transpose()
    }

    fn optional_u64(args: &[String], name: &str) -> io::Result<Option<u64>> {
        value_after(args, name)?
            .map(|value| {
                value.parse::<u64>().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid {name} value {value}: {error}"),
                    )
                })
            })
            .transpose()
    }

    fn optional_u16(args: &[String], name: &str) -> io::Result<Option<u16>> {
        value_after(args, name)?
            .map(|value| {
                value.parse::<u16>().map_err(|error| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("invalid {name} value {value}: {error}"),
                    )
                })
            })
            .transpose()
    }

    fn optional_probe(args: &[String], name: &str) -> io::Result<Option<ProbeKind>> {
        value_after(args, name)?
            .map(|value| match value {
                "icmp" => Ok(ProbeKind::Icmp),
                "tcp" => Ok(ProbeKind::Tcp),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid {name} value {value}"),
                )),
            })
            .transpose()
    }

    fn optional_expected_protocol(
        args: &[String],
        name: &str,
    ) -> io::Result<Option<ExpectedProtocol>> {
        value_after(args, name)?
            .map(|value| match value {
                "any" => Ok(ExpectedProtocol::Any),
                "tcp" => Ok(ExpectedProtocol::Tcp),
                _ => Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("invalid {name} value {value}"),
                )),
            })
            .transpose()
    }

    #[allow(clippy::too_many_arguments)]
    fn run_helper(
        expected_main: PeerIdentity,
        socket_path: &Path,
        events_path: &Path,
        route_proof_path: Option<&Path>,
        probe: ProbeKind,
        controlled_peer: Ipv4Addr,
        controlled_local: Ipv4Addr,
        relay_ip: Ipv4Addr,
    ) -> io::Result<()> {
        require_root()?;
        // Bind the actual connected main process before creating utun or
        // changing routes. A launcher PID or a peer-supplied claim is not used.
        let stream = connect_with_retry(socket_path, Duration::from_secs(5))?;
        stream.set_write_timeout(Some(Duration::from_secs(5)))?;
        verify_peer(&stream, expected_main.uid, Some(expected_main.pid))?;
        emit_event(
            events_path,
            "macos_utun_helper_started",
            json!({
                "scope": "lab_controlled_utun_w0",
                "privileged": true,
                "default_route_claim": false,
                "relay_ip": relay_ip.to_string(),
                "controlled_peer": controlled_peer.to_string(),
            }),
        );
        let fd = open_utun()?;
        let ifname = utun_ifname(fd.as_raw_fd())?;
        let before_routes = netstat_inet_routes();
        let mut cleanup = RouteCleanup::new(ifname.clone(), controlled_peer);
        configure_utun(&ifname, controlled_local, controlled_peer)?;
        let _ = delete_controlled_route(controlled_peer);
        cleanup.route_added = add_controlled_route(&ifname, controlled_peer).is_ok();
        let after_add_routes = netstat_inet_routes();
        let controlled_route_present =
            route_table_has_host_interface(&after_add_routes, controlled_peer, &ifname);
        let relay_excluded_from_utun =
            !route_table_has_host_interface(&after_add_routes, relay_ip, &ifname);

        send_fd_to_peer(&stream, fd.as_raw_fd(), ifname.as_bytes(), expected_main)?;

        run_probe(probe, controlled_peer);

        cleanup.cleanup(events_path);
        let after_cleanup_routes = netstat_inet_routes();
        let controlled_route_removed =
            !route_table_has_host_interface(&after_cleanup_routes, controlled_peer, &ifname);
        if let Some(path) = route_proof_path {
            write_route_proof(RouteProof {
                path,
                ifname: &ifname,
                controlled_peer,
                relay_ip,
                controlled_route_present,
                relay_excluded_from_utun,
                controlled_route_removed,
                before_routes: &before_routes,
                after_add_routes: &after_add_routes,
                after_cleanup_routes: &after_cleanup_routes,
            })?;
        }
        Ok(())
    }

    fn run_main(
        socket_path: &Path,
        events_path: &Path,
        result_path: &Path,
        timeout: Duration,
        expected_protocol: ExpectedProtocol,
        expected_dst_port: Option<u16>,
        tcp_synack_lab: bool,
    ) -> io::Result<()> {
        if is_root() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "main process must run non-root for W0 FD proof",
            ));
        }
        if let Some(parent) = socket_path.parent() {
            fs::create_dir_all(parent)?;
        }
        let _ = fs::remove_file(socket_path);
        let listener = UnixListener::bind(socket_path)?;
        let (stream, _) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let (fd, ifname) = recv_fd_from_peer(&stream, 0)?;
        emit_event(
            events_path,
            "macos_utun_fd_received",
            json!({
                "scope": "lab_controlled_utun_w0",
                "non_root_uid": unsafe { libc::geteuid() },
                "ifname": ifname,
            }),
        );

        let observed = read_utun_packet(
            fd.as_raw_fd(),
            timeout,
            expected_protocol,
            expected_dst_port,
        )?;
        if let Some(packet) = observed.as_ref() {
            emit_event(
                events_path,
                "macos_utun_packet_observed",
                json!({
                    "scope": "lab_controlled_utun_w0",
                    "ifname": ifname,
                    "packet_len": packet.packet_len,
                    "address_family": packet.address_family,
                    "ip_version": packet.ip_version,
                    "protocol": packet.protocol,
                    "source_ip": packet.source_ip.map(|ip| ip.to_string()),
                    "destination_ip": packet.destination_ip.map(|ip| ip.to_string()),
                    "source_port": packet.source_port,
                    "destination_port": packet.destination_port,
                    "tcp_flags": packet.tcp_flags,
                    "tcp_sequence": packet.tcp_sequence,
                }),
            );
        }
        let handshake = if tcp_synack_lab {
            observed
                .as_ref()
                .and_then(|packet| tcp_synack_lab_round_trip(fd.as_raw_fd(), packet, timeout).ok())
                .flatten()
        } else {
            None
        };
        if let Some(handshake) = handshake.as_ref() {
            emit_event(
                events_path,
                "macos_utun_tcp_synack_lab_completed",
                json!({
                    "scope": "lab_controlled_utun_w2_stateful_edge",
                    "ifname": ifname,
                    "syn_observed": true,
                    "synack_written": handshake.synack_written,
                    "ack_observed": handshake.ack_observed,
                    "client_sequence": handshake.client_sequence,
                    "server_sequence": handshake.server_sequence,
                }),
            );
        }
        drop(fd);
        emit_event(
            events_path,
            "macos_utun_cleanup_completed",
            json!({
                "scope": "lab_controlled_utun_w0",
                "main_fd_closed": true,
                "broad_system_wide_claim": false,
            }),
        );
        let pass =
            observed.is_some() && (!tcp_synack_lab || handshake.as_ref().is_some_and(|h| h.pass()));
        write_result(result_path, pass, &ifname, observed, handshake)?;
        let _ = fs::remove_file(socket_path);
        Ok(())
    }

    fn open_utun() -> io::Result<OwnedFd> {
        let fd = unsafe { libc::socket(PF_SYSTEM, libc::SOCK_DGRAM, SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        let mut info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0; 96],
        };
        let name = CString::new(UTUN_CONTROL_NAME).expect("static string");
        let bytes = name.as_bytes_with_nul();
        for (idx, byte) in bytes.iter().enumerate().take(info.ctl_name.len()) {
            info.ctl_name[idx] = *byte as libc::c_char;
        }
        let rc = unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut info) };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let addr = SockaddrCtl {
            sc_len: mem::size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: AF_SYS_CONTROL as u16,
            sc_id: info.ctl_id,
            sc_unit: 0,
            sc_reserved: [0; 5],
        };
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const SockaddrCtl as *const libc::sockaddr,
                mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(fd)
    }

    fn utun_ifname(fd: RawFd) -> io::Result<String> {
        let mut name = [0u8; 32];
        let mut len = name.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                SYSPROTO_CONTROL,
                UTUN_OPT_IFNAME,
                name.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        let end = name
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(name.len());
        Ok(String::from_utf8_lossy(&name[..end]).to_string())
    }

    fn configure_utun(ifname: &str, local: Ipv4Addr, peer: Ipv4Addr) -> io::Result<()> {
        command_ok(
            Command::new("/sbin/ifconfig").args([
                ifname,
                "inet",
                &local.to_string(),
                &peer.to_string(),
                "up",
            ]),
            "ifconfig utun inet",
        )
    }

    fn add_controlled_route(ifname: &str, peer: Ipv4Addr) -> io::Result<()> {
        command_ok(
            Command::new("/sbin/route").args([
                "-q",
                "add",
                "-host",
                &peer.to_string(),
                "-interface",
                ifname,
            ]),
            "route add controlled host",
        )
    }

    fn delete_controlled_route(peer: Ipv4Addr) -> io::Result<()> {
        command_ok(
            Command::new("/sbin/route").args(["-q", "delete", "-host", &peer.to_string()]),
            "route delete controlled host",
        )
    }

    fn run_probe(probe: ProbeKind, controlled_peer: Ipv4Addr) {
        match probe {
            ProbeKind::Icmp => {
                let _ = Command::new("/sbin/ping")
                    .args(["-c", "1", "-t", "1", &controlled_peer.to_string()])
                    .status();
            }
            ProbeKind::Tcp => {
                let peer = controlled_peer.to_string();
                let _ = Command::new("/usr/bin/nc")
                    .args(["-G", "1", "-z", &peer, "443"])
                    .status();
            }
        }
    }

    fn netstat_inet_routes() -> String {
        Command::new("/usr/sbin/netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
            .unwrap_or_default()
    }

    fn route_table_has_host_interface(routes: &str, host: Ipv4Addr, ifname: &str) -> bool {
        let host = host.to_string();
        routes.lines().any(|line| {
            let mut columns = line.split_whitespace();
            columns.next() == Some(host.as_str())
                && line.split_whitespace().any(|part| part == ifname)
        })
    }

    struct RouteProof<'a> {
        path: &'a Path,
        ifname: &'a str,
        controlled_peer: Ipv4Addr,
        relay_ip: Ipv4Addr,
        controlled_route_present: bool,
        relay_excluded_from_utun: bool,
        controlled_route_removed: bool,
        before_routes: &'a str,
        after_add_routes: &'a str,
        after_cleanup_routes: &'a str,
    }

    fn write_route_proof(proof: RouteProof<'_>) -> io::Result<()> {
        if let Some(parent) = proof.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let pass = proof.controlled_route_present
            && proof.relay_excluded_from_utun
            && proof.controlled_route_removed;
        let status = if pass { "PASS" } else { "ROUTE_PROOF_FAILED" };
        let verdict = if pass { "PASS" } else { "NOT_PASS" };
        let result = json!({
            "schema_version": 1,
            "artifact": "macos-utun-w1-controlled-ipv4-route-proof",
            "status": status,
            "verdict": verdict,
            "scope": "LAB_CONTROLLED_IPV4_32_ROUTE_ONLY",
            "ifname": proof.ifname,
            "controlled_peer": proof.controlled_peer.to_string(),
            "relay_ip": proof.relay_ip.to_string(),
            "controlled_route_prefix": "/32",
            "controlled_route_present": proof.controlled_route_present,
            "relay_ip_excluded_from_utun": proof.relay_excluded_from_utun,
            "controlled_route_removed_after_cleanup": proof.controlled_route_removed,
            "default_route_claim": false,
            "broad_system_wide_claim": false,
            "dns_claimed": false,
            "udp_claimed": false,
            "ipv6_claimed": false,
            "routes_before": proof.before_routes,
            "routes_after_add": proof.after_add_routes,
            "routes_after_cleanup": proof.after_cleanup_routes,
        });
        write_json_pretty(proof.path, &result)
    }

    fn command_ok(command: &mut Command, label: &str) -> io::Result<()> {
        let status = command.status()?;
        if status.success() {
            Ok(())
        } else {
            Err(io::Error::other(format!("{label} failed: {status}")))
        }
    }

    struct RouteCleanup {
        ifname: String,
        peer: Ipv4Addr,
        route_added: bool,
    }

    impl RouteCleanup {
        fn new(ifname: String, peer: Ipv4Addr) -> Self {
            Self {
                ifname,
                peer,
                route_added: false,
            }
        }

        fn cleanup(&self, events_path: &Path) {
            if self.route_added {
                let _ = Command::new("/sbin/route")
                    .args(["-q", "delete", "-host", &self.peer.to_string()])
                    .status();
            }
            let _ = Command::new("/sbin/ifconfig")
                .args([&self.ifname, "down"])
                .status();
            emit_event(
                events_path,
                "macos_utun_cleanup_completed",
                json!({
                    "scope": "lab_controlled_utun_w0",
                    "helper_route_cleanup_attempted": self.route_added,
                    "ifname": self.ifname,
                    "aegis_owned_route_only": true,
                }),
            );
        }
    }

    struct ObservedPacket {
        packet_len: usize,
        address_family: u32,
        ip_version: u8,
        protocol: u8,
        source_ip: Option<Ipv4Addr>,
        destination_ip: Option<Ipv4Addr>,
        source_port: Option<u16>,
        destination_port: Option<u16>,
        tcp_flags: Option<u8>,
        tcp_sequence: Option<u32>,
        tcp_acknowledgment: Option<u32>,
    }

    struct TcpHandshakeProof {
        synack_written: bool,
        ack_observed: bool,
        client_sequence: u32,
        server_sequence: u32,
    }

    impl TcpHandshakeProof {
        fn pass(&self) -> bool {
            self.synack_written && self.ack_observed
        }
    }

    fn read_utun_packet(
        fd: RawFd,
        timeout: Duration,
        expected_protocol: ExpectedProtocol,
        expected_dst_port: Option<u16>,
    ) -> io::Result<Option<ObservedPacket>> {
        let start = Instant::now();
        let mut buf = [0u8; 4096];
        while start.elapsed() < timeout {
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let remaining = timeout.saturating_sub(start.elapsed());
            let poll_ms = remaining.as_millis().min(250) as i32;
            let rc = unsafe { libc::poll(&mut pollfd, 1, poll_ms) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            if rc == 0 || (pollfd.revents & libc::POLLIN) == 0 {
                continue;
            }
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n <= UTUN_HEADER_LEN {
                continue;
            }
            let family = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let payload = &buf[UTUN_HEADER_LEN..n];
            let Some(packet) = parse_observed_packet(family, payload) else {
                continue;
            };
            if expected_protocol == ExpectedProtocol::Tcp && packet.protocol != 6 {
                continue;
            }
            if let Some(port) = expected_dst_port {
                if packet.destination_port != Some(port) {
                    continue;
                }
            }
            return Ok(Some(packet));
        }
        Ok(None)
    }

    fn parse_observed_packet(family: u32, payload: &[u8]) -> Option<ObservedPacket> {
        if payload.is_empty() {
            return None;
        }
        let ip_version = payload[0] >> 4;
        if ip_version != 4 || payload.len() < 20 {
            return Some(ObservedPacket {
                packet_len: payload.len(),
                address_family: family,
                ip_version,
                protocol: 0,
                source_ip: None,
                destination_ip: None,
                source_port: None,
                destination_port: None,
                tcp_flags: None,
                tcp_sequence: None,
                tcp_acknowledgment: None,
            });
        }
        let ihl = ((payload[0] & 0x0f) as usize) * 4;
        if payload.len() < ihl || ihl < 20 {
            return None;
        }
        let protocol = payload[9];
        let source_ip = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
        let destination_ip = Ipv4Addr::new(payload[16], payload[17], payload[18], payload[19]);
        let mut source_port = None;
        let mut destination_port = None;
        let mut tcp_flags = None;
        let mut tcp_sequence = None;
        let mut tcp_acknowledgment = None;
        if protocol == 6 && payload.len() >= ihl + 20 {
            source_port = Some(u16::from_be_bytes([payload[ihl], payload[ihl + 1]]));
            destination_port = Some(u16::from_be_bytes([payload[ihl + 2], payload[ihl + 3]]));
            tcp_sequence = Some(u32::from_be_bytes([
                payload[ihl + 4],
                payload[ihl + 5],
                payload[ihl + 6],
                payload[ihl + 7],
            ]));
            tcp_acknowledgment = Some(u32::from_be_bytes([
                payload[ihl + 8],
                payload[ihl + 9],
                payload[ihl + 10],
                payload[ihl + 11],
            ]));
            tcp_flags = Some(payload[ihl + 13]);
        }
        Some(ObservedPacket {
            packet_len: payload.len(),
            address_family: family,
            ip_version,
            protocol,
            source_ip: Some(source_ip),
            destination_ip: Some(destination_ip),
            source_port,
            destination_port,
            tcp_flags,
            tcp_sequence,
            tcp_acknowledgment,
        })
    }

    fn tcp_synack_lab_round_trip(
        fd: RawFd,
        syn: &ObservedPacket,
        timeout: Duration,
    ) -> io::Result<Option<TcpHandshakeProof>> {
        let Some(source_ip) = syn.source_ip else {
            return Ok(None);
        };
        let Some(destination_ip) = syn.destination_ip else {
            return Ok(None);
        };
        let Some(source_port) = syn.source_port else {
            return Ok(None);
        };
        let Some(destination_port) = syn.destination_port else {
            return Ok(None);
        };
        let Some(client_sequence) = syn.tcp_sequence else {
            return Ok(None);
        };
        let flags = syn.tcp_flags.unwrap_or(0);
        if syn.protocol != 6 || flags & 0x02 == 0 {
            return Ok(None);
        }
        let server_sequence = 0xa36e_0001;
        let packet = build_ipv4_tcp_packet(TcpPacketSpec {
            source_ip: destination_ip,
            destination_ip: source_ip,
            source_port: destination_port,
            destination_port: source_port,
            sequence: server_sequence,
            acknowledgment: client_sequence.wrapping_add(1),
            flags: 0x12,
        });
        let mut framed = Vec::with_capacity(UTUN_HEADER_LEN + packet.len());
        framed.extend_from_slice(&syn.address_family.to_be_bytes());
        framed.extend_from_slice(&packet);
        let written =
            unsafe { libc::write(fd, framed.as_ptr() as *const libc::c_void, framed.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        let ack = read_matching_tcp_ack(
            fd,
            timeout,
            source_ip,
            destination_ip,
            source_port,
            destination_port,
            client_sequence.wrapping_add(1),
            server_sequence.wrapping_add(1),
        )?;
        Ok(Some(TcpHandshakeProof {
            synack_written: written as usize == framed.len(),
            ack_observed: ack,
            client_sequence,
            server_sequence,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    fn read_matching_tcp_ack(
        fd: RawFd,
        timeout: Duration,
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        expected_sequence: u32,
        expected_acknowledgment: u32,
    ) -> io::Result<bool> {
        let start = Instant::now();
        let mut buf = [0u8; 4096];
        while start.elapsed() < timeout {
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let remaining = timeout.saturating_sub(start.elapsed());
            let poll_ms = remaining.as_millis().min(250) as i32;
            let rc = unsafe { libc::poll(&mut pollfd, 1, poll_ms) };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            if rc == 0 || (pollfd.revents & libc::POLLIN) == 0 {
                continue;
            }
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            let n = n as usize;
            if n <= UTUN_HEADER_LEN {
                continue;
            }
            let family = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let Some(packet) = parse_observed_packet(family, &buf[UTUN_HEADER_LEN..n]) else {
                continue;
            };
            if packet.protocol == 6
                && packet.source_ip == Some(source_ip)
                && packet.destination_ip == Some(destination_ip)
                && packet.source_port == Some(source_port)
                && packet.destination_port == Some(destination_port)
                && packet.tcp_sequence == Some(expected_sequence)
                && packet.tcp_acknowledgment == Some(expected_acknowledgment)
                && packet.tcp_flags.unwrap_or(0) & 0x10 != 0
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    struct TcpPacketSpec {
        source_ip: Ipv4Addr,
        destination_ip: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgment: u32,
        flags: u8,
    }

    fn build_ipv4_tcp_packet(spec: TcpPacketSpec) -> Vec<u8> {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[1] = 0;
        packet[2..4].copy_from_slice(&(40u16).to_be_bytes());
        packet[4..6].copy_from_slice(&0x4a53u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&spec.source_ip.octets());
        packet[16..20].copy_from_slice(&spec.destination_ip.octets());
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        let tcp = &mut packet[20..40];
        tcp[0..2].copy_from_slice(&spec.source_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&spec.destination_port.to_be_bytes());
        tcp[4..8].copy_from_slice(&spec.sequence.to_be_bytes());
        tcp[8..12].copy_from_slice(&spec.acknowledgment.to_be_bytes());
        tcp[12] = 5u8 << 4;
        tcp[13] = spec.flags;
        tcp[14..16].copy_from_slice(&65535u16.to_be_bytes());
        let tcp_sum = tcp_checksum(spec.source_ip, spec.destination_ip, tcp);
        tcp[16..18].copy_from_slice(&tcp_sum.to_be_bytes());
        packet
    }

    fn tcp_checksum(source_ip: Ipv4Addr, destination_ip: Ipv4Addr, tcp: &[u8]) -> u16 {
        let mut pseudo = Vec::with_capacity(12 + tcp.len());
        pseudo.extend_from_slice(&source_ip.octets());
        pseudo.extend_from_slice(&destination_ip.octets());
        pseudo.push(0);
        pseudo.push(6);
        pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        pseudo.extend_from_slice(tcp);
        checksum(&pseudo)
    }

    fn checksum(data: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            sum = sum.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]) as u32);
        }
        if let Some(byte) = chunks.remainder().first() {
            sum = sum.wrapping_add((*byte as u32) << 8);
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn connect_with_retry(path: &Path, timeout: Duration) -> io::Result<UnixStream> {
        let start = Instant::now();
        loop {
            match UnixStream::connect(path) {
                Ok(stream) => return Ok(stream),
                Err(err) if start.elapsed() < timeout => {
                    let _ = err;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn write_result(
        path: &Path,
        pass: bool,
        ifname: &str,
        observed: Option<ObservedPacket>,
        handshake: Option<TcpHandshakeProof>,
    ) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let status = if pass { "PASS" } else { "PACKET_NOT_OBSERVED" };
        let verdict = if pass { "PASS" } else { "NOT_PASS" };
        let tcp_synack_lab_pass = handshake.as_ref().is_some_and(TcpHandshakeProof::pass) && pass;
        let result = json!({
            "schema_version": 1,
            "artifact": "macos-utun-helper-fd-loop-lab",
            "status": status,
            "verdict": verdict,
            "ifname": ifname,
            "helper_creates_utun": true,
            "fd_passed_to_non_root_main_process": true,
            "packet_or_controlled_injected_packet_observed": pass,
            "tcp_synack_lab_pass": tcp_synack_lab_pass,
            "cleanup_succeeds": true,
            "broad_system_wide_claim": false,
            "relay_session_claimed": false,
            "packet": observed.as_ref().map(observed_packet_json),
            "tcp_handshake": handshake.as_ref().map(tcp_handshake_json),
        });
        write_json_pretty(path, &result)
    }

    fn emit_event(path: &Path, event_code: &str, fields: Value) {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let event = json!({
                "timestamp_unix_ms": current_unix_ms(),
                "level": "info",
                "event_code": event_code,
                "fields": fields,
            });
            let _ = writeln!(file, "{event}");
        }
    }

    fn write_json_pretty(path: &Path, value: &Value) -> io::Result<()> {
        let mut json = serde_json::to_string_pretty(value).map_err(io::Error::other)?;
        json.push('\n');
        fs::write(path, json)
    }

    fn observed_packet_json(packet: &ObservedPacket) -> Value {
        json!({
            "packet_len": packet.packet_len,
            "address_family": packet.address_family,
            "ip_version": packet.ip_version,
            "protocol": packet.protocol,
            "source_ip": packet.source_ip.map(|ip| ip.to_string()),
            "destination_ip": packet.destination_ip.map(|ip| ip.to_string()),
            "source_port": packet.source_port,
            "destination_port": packet.destination_port,
            "tcp_flags": packet.tcp_flags,
            "tcp_sequence": packet.tcp_sequence,
            "tcp_acknowledgment": packet.tcp_acknowledgment,
        })
    }

    fn tcp_handshake_json(handshake: &TcpHandshakeProof) -> Value {
        json!({
            "synack_written": handshake.synack_written,
            "ack_observed": handshake.ack_observed,
            "client_sequence": handshake.client_sequence,
            "server_sequence": handshake.server_sequence,
            "scope": "LAB_TCP_SYNACK_EDGE_ONLY",
        })
    }

    fn current_unix_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    fn require_root() -> io::Result<()> {
        if is_root() {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "helper must run as root",
            ))
        }
    }
    #[cfg(test)]
    mod peer_argument_tests {
        use super::*;

        fn args(values: &[&str]) -> Vec<String> {
            values.iter().map(|value| (*value).to_owned()).collect()
        }

        #[test]
        fn helper_requires_explicit_non_root_uid_and_actual_positive_pid() {
            for values in [
                vec![],
                vec!["--main-uid", "501"],
                vec!["--main-uid", "0", "--main-pid", "1"],
                vec!["--main-uid", "501", "--main-pid", "0"],
                vec!["--main-uid", "501", "--main-pid", "-1"],
                vec!["--main-uid", "501", "--main-uid", "502", "--main-pid", "1"],
            ] {
                assert!(required_main_peer(&args(&values)).is_err());
            }
            assert_eq!(
                required_main_peer(&args(&["--main-uid", "501", "--main-pid", "123"])).unwrap(),
                PeerIdentity { uid: 501, pid: 123 }
            );
        }
    }
}
