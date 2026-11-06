use super::*;
#[cfg(windows)]
use aegis_core::tunnel_policy::Prefix;
#[cfg(windows)]
use aegis_core::windows_tunnel::{
    firewall::ScopedProtection, network::NetworkGuard, wintun::Wintun,
};
use aegis_core::{
    tunnel_policy::{CLIENT_V4, CLIENT_V6},
    TunnelTransportFamily as Family,
};
use std::{
    net::{IpAddr, SocketAddr},
    sync::mpsc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[cfg(all(windows, feature = "windows-host-acceptance"))]
mod full_host;
mod native_byte_diagnostics;
#[cfg(all(windows, feature = "windows-host-acceptance"))]
mod owned_process;
mod progress_deadline;
#[cfg(windows)]
mod soak;

struct EngineStop {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<io::Result<TunnelStats>>>,
}
impl Drop for EngineStop {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            eprintln!("native engine cleanup result: {:?}", t.join());
        }
    }
}
struct Channels {
    rx: mpsc::Receiver<Vec<u8>>,
    tx: mpsc::SyncSender<Vec<u8>>,
}
impl PacketIo for Channels {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.rx.try_recv() {
            Ok(p) => Ok(Some(p)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(_) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }
    fn send(&mut self, p: &[u8]) -> io::Result<()> {
        self.tx
            .try_send(p.to_vec())
            .map_err(|_| io::ErrorKind::WouldBlock.into())
    }
}
fn payload() -> Vec<u8> {
    (0..2 * 1024 * 1024)
        .map(|i| ((i * 71 + i / 251) % 256) as u8)
        .collect()
}
async fn echo_tcp(ip: IpAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    echo_tcp_observed(ip, Arc::new(std::sync::atomic::AtomicUsize::new(0))).await
}
async fn echo_tcp_observed(
    ip: IpAddr,
    received: Arc<std::sync::atomic::AtomicUsize>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        let mut buffer = [0; 16384];
        loop {
            let n = socket.read(&mut buffer).await.unwrap();
            if n == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..n]);
            received.fetch_add(n, Ordering::Relaxed);
        }
        socket.write_all(&bytes).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    (address, job)
}

// This diagnostic fixture keeps the original accept/read-until-EOF/write_all/
// shutdown sequence. Counters observe completion; they do not repair transfers.
#[cfg(windows)]
async fn echo_tcp_native_stages(
    ip: IpAddr,
    received: Arc<std::sync::atomic::AtomicUsize>,
    stages: Arc<native_byte_diagnostics::Stages>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind((ip, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = vec![];
        let mut buffer = [0; 16384];
        loop {
            stages.echo_read.store(1, Ordering::Relaxed);
            let result = socket.read(&mut buffer).await;
            stages
                .echo_read
                .store(if result.is_ok() { 2 } else { 3 }, Ordering::Relaxed);
            let n = result.unwrap();
            if n == 0 {
                stages.echo_eof.store(1, Ordering::Relaxed);
                break;
            }
            bytes.extend_from_slice(&buffer[..n]);
            received.fetch_add(n, Ordering::Relaxed);
            stages.echo_read_bytes.fetch_add(n, Ordering::Relaxed);
        }
        stages
            .echo_reply_bytes
            .store(bytes.len(), Ordering::Relaxed);
        stages.echo_write.store(1, Ordering::Relaxed);
        let result = socket.write_all(&bytes).await;
        stages
            .echo_write
            .store(if result.is_ok() { 2 } else { 3 }, Ordering::Relaxed);
        result.unwrap();
        stages.echo_shutdown.store(1, Ordering::Relaxed);
        let result = socket.shutdown().await;
        stages
            .echo_shutdown
            .store(if result.is_ok() { 2 } else { 3 }, Ordering::Relaxed);
        result.unwrap();
    });
    (address, job)
}

async fn echo_udp(ip: IpAddr) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = tokio::net::UdpSocket::bind((ip, 0)).await.unwrap();
    aegis_core::native_udp::prepare(&socket).unwrap();
    let address = socket.local_addr().unwrap();
    let job = tokio::spawn(async move {
        let mut buffer = vec![0; 65535];
        loop {
            let (n, peer) = socket.recv_from(&mut buffer).await.unwrap();
            socket.send_to(&buffer[..n], peer).await.unwrap();
        }
    });
    (address, job)
}
fn host_interface(v6: bool) -> (Interface, Phy, SocketSet<'static>) {
    let mut phy = Phy {
        input: VecDeque::new(),
        output: VecDeque::new(),
        mtu: 1280,
    };
    let mut iface = Interface::new(
        Config::new(HardwareAddress::Ip),
        &mut phy,
        SmolInstant::now(),
    );
    iface.update_ip_addrs(|a| {
        a.push(IpCidr::new(
            if v6 {
                CLIENT_V6.into()
            } else {
                CLIENT_V4.into()
            },
            if v6 { 128 } else { 32 },
        ))
        .unwrap();
    });
    if v6 {
        iface
            .routes_mut()
            .add_default_ipv6_route(CLIENT_V6)
            .unwrap();
    } else {
        iface
            .routes_mut()
            .add_default_ipv4_route(CLIENT_V4)
            .unwrap();
    }
    (iface, phy, SocketSet::new(vec![]))
}
fn virtual_transfer(
    settings: RelaySettings,
    tcp_target: SocketAddr,
    udp_target: SocketAddr,
) -> TunnelStats {
    let large_udp = settings.udp_transport_priority.as_ref().unwrap()[0] == Family::GrpcDatagram;
    let (input_tx, input_rx) = mpsc::sync_channel(512);
    let (output_tx, output_rx) = mpsc::sync_channel(512);
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let mut guard = EngineStop {
        stop,
        thread: Some(std::thread::spawn(move || {
            run(
                &mut Channels {
                    rx: input_rx,
                    tx: output_tx,
                },
                settings,
                thread_stop,
                32,
                Duration::from_secs(60),
                1280,
                "9.9.9.9:53".parse().unwrap(),
            )
        })),
    };
    let (mut iface, mut phy, mut sockets) = host_interface(tcp_target.is_ipv6());
    let mut tcp = tcp::Socket::new(
        tcp::SocketBuffer::new(vec![0; 65536]),
        tcp::SocketBuffer::new(vec![0; 65536]),
    );
    tcp.connect(
        iface.context(),
        (IpAddress::from(tcp_target.ip()), tcp_target.port()),
        35001,
    )
    .unwrap();
    let tcp_handle = sockets.add(tcp);
    let mut udp = udp::Socket::new(
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 65536]),
        udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 32], vec![0; 65536]),
    );
    udp.bind(35002).unwrap();
    let udp_handle = sockets.add(udp);
    let request = payload();
    let mut sent = 0;
    let mut response = vec![];
    let mut fin = false;
    let mut udp_received = 0;
    let mut udp_sent = 0;
    // On a loaded Windows runner, uploading 2 MiB can use almost the entire
    // former 45-second budget before FIN. Keep a strict no-progress deadline
    // and a separate overall cap so a healthy response has time to arrive.
    let mut deadline = progress_deadline::ProgressDeadline::new(
        Instant::now(),
        Duration::from_secs(45),
        Duration::from_secs(180),
    );
    let mut reassembly = fragments::Fragments::default();
    loop {
        while let Ok(packet) = output_rx.try_recv() {
            if let Some(packet) = reassembly.accept(&packet).unwrap() {
                phy.input.push_back(packet);
            }
        }
        iface.poll(SmolInstant::now(), &mut phy, &mut sockets);
        let socket = sockets.get_mut::<tcp::Socket>(tcp_handle);
        if socket.can_send() && sent < request.len() {
            sent += socket.send_slice(&request[sent..]).unwrap();
        }
        if sent == request.len() && !fin {
            socket.close();
            fin = true;
        }
        while socket.can_recv() {
            socket
                .recv(|bytes| {
                    response.extend_from_slice(bytes);
                    (bytes.len(), ())
                })
                .unwrap();
        }
        let done = fin && !socket.may_recv();
        let udp = sockets.get_mut::<udp::Socket>(udp_handle);
        if udp_sent == udp_received && udp_sent < 20 {
            let mut p = vec![
                udp_sent as u8;
                if udp_sent == 3 && large_udp {
                    65000
                } else {
                    1200
                }
            ];
            p[1] = 173;
            for packet in fragments::udp_packets(
                if udp_target.is_ipv6() {
                    CLIENT_V6.into()
                } else {
                    CLIENT_V4.into()
                },
                35002,
                udp_target.ip(),
                udp_target.port(),
                &p,
                1280,
            )
            .unwrap()
            {
                input_tx.send(packet).unwrap();
            }
            udp_sent += 1;
        }
        while udp.can_recv() {
            let (p, meta) = udp.recv().unwrap();
            assert_eq!(meta.endpoint.port, udp_target.port());
            assert_eq!(meta.endpoint.addr, IpAddress::from(udp_target.ip()));
            assert_eq!(
                p,
                vec![
                    udp_received as u8;
                    if udp_received == 3 && large_udp {
                        65000
                    } else {
                        1200
                    }
                ]
                .iter()
                .enumerate()
                .map(|(i, b)| if i == 1 { 173 } else { *b })
                .collect::<Vec<_>>()
            );
            udp_received += 1;
        }
        iface.poll(SmolInstant::now(), &mut phy, &mut sockets);
        while let Some(p) = phy.output.pop_front() {
            input_tx.send(p).unwrap();
        }
        assert!(
            !deadline.expired(Instant::now(), (sent, response.len(), udp_received)),
            "timeout: TCP sent={sent} received={} UDP={udp_received}",
            response.len()
        );
        if done && udp_received == 20 {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(
        response, request,
        "2 MiB response after client FIN must be lossless"
    );
    guard.stop.store(true, Ordering::Release);
    guard.thread.take().unwrap().join().unwrap().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_stack_packet_engine_preserves_tcp_fin_and_persistent_udp() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (cfg, server) = crate::tests::start_local_masque_server().await;
    for ip in ["127.0.0.1", "::1"] {
        for udp_family in [Family::GrpcDatagram, Family::MasqueDerived] {
            let (tcp, echo) = echo_tcp(ip.parse().unwrap()).await;
            let (udp, udp_echo) = echo_udp(ip.parse().unwrap()).await;
            let mut settings = cfg.relay.clone();
            // The all-features fresh-legacy mode admits only raw LegacyTls TCP.
            // Keep the same full TCP/FIN and both UDP-family transfer assertions.
            settings.transport_priority = vec![if cfg!(feature = "legacy-challenge-v1") {
                Family::LegacyTls
            } else if udp_family == Family::MasqueDerived {
                Family::MasqueDerived
            } else {
                Family::GrpcStream
            }];
            settings.udp_transport_priority = Some(vec![udp_family]);
            let stats = tokio::task::spawn_blocking(move || virtual_transfer(settings, tcp, udp))
                .await
                .unwrap();
            assert_eq!(stats.tcp_flows_opened, 1);
            assert_eq!(stats.udp_sessions_opened, 1);
            assert_eq!(stats.tcp_egress_bytes, payload().len() as u64);
            echo.await.unwrap();
            udp_echo.abort();
        }
    }
    server.abort();
}

// Optional bounded wire diagnostics for this synthetic native test only.
// This observes the test adapter, not independent host-wide leak protection.
#[cfg(windows)]
struct RecordedPackets<T> {
    inner: T,
    file: Option<std::io::BufWriter<std::fs::File>>,
    bytes: usize,
    enabled: Option<Arc<AtomicBool>>,
}
#[cfg(windows)]
impl<T: PacketIo> RecordedPackets<T> {
    fn new(inner: T) -> io::Result<Self> {
        Self::with_recording(inner, "AEGIS_TEST_NATIVE_PCAP", None)
    }
    fn with_recording(
        inner: T,
        variable: &str,
        enabled: Option<Arc<AtomicBool>>,
    ) -> io::Result<Self> {
        use std::io::Write;
        let file = std::env::var_os(variable)
            .map(|path| {
                let mut file = std::io::BufWriter::new(std::fs::File::create_new(path)?);
                file.write_all(&0xa1b2c3d4u32.to_le_bytes())?;
                file.write_all(&2u16.to_le_bytes())?;
                file.write_all(&4u16.to_le_bytes())?;
                for value in [0u32, 0, 65535, 101] {
                    file.write_all(&value.to_le_bytes())?;
                }
                Ok::<_, io::Error>(file)
            })
            .transpose()?;
        Ok(Self {
            inner,
            file,
            bytes: 24,
            enabled,
        })
    }
    fn record(&mut self, packet: &[u8]) -> io::Result<()> {
        use std::io::Write;
        if self
            .enabled
            .as_ref()
            .is_some_and(|enabled| !enabled.load(Ordering::Acquire))
        {
            return Ok(());
        }
        let Some(file) = self.file.as_mut() else {
            return Ok(());
        };
        self.bytes += packet.len() + 16;
        if packet.len() > 65535 || self.bytes > 32 * 1024 * 1024 {
            return Err(io::Error::other(
                "synthetic packet recording bound exceeded",
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?;
        for value in [
            now.as_secs() as u32,
            now.subsec_micros(),
            packet.len() as u32,
            packet.len() as u32,
        ] {
            file.write_all(&value.to_le_bytes())?;
        }
        file.write_all(packet)
    }
}
#[cfg(windows)]
impl<T: PacketIo> PacketIo for RecordedPackets<T> {
    fn receive(&mut self) -> io::Result<Option<Vec<u8>>> {
        let packet = self.inner.receive()?;
        if let Some(packet) = packet.as_ref() {
            self.record(packet)?;
        }
        Ok(packet)
    }
    fn send(&mut self, packet: &[u8]) -> io::Result<()> {
        self.inner.send(packet)?;
        self.record(packet)
    }
}

#[cfg(windows)]
fn dns_question(host: &str) -> Vec<u8> {
    let mut p = vec![0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in host.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.extend_from_slice(&[0, 0, 1, 0, 1]);
    p
}

#[cfg(windows)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "administrator and AEGIS_TEST_WINTUN; isolated adapter, synthetic routes, WFP scoped only to the test executable"]
async fn real_windows_sockets_dns_tcp_udp_through_signed_wintun() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (mut cfg, server) = crate::tests::start_local_masque_server().await;
    cfg.relay.transport_priority = vec![Family::GrpcStream];
    cfg.relay.udp_transport_priority = Some(vec![Family::GrpcDatagram]);
    // Observe bytes at the real echo endpoint, not merely buffered OS writes.
    let uploaded = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let downloaded = std::sync::atomic::AtomicUsize::new(0);
    let completed_phases = std::sync::atomic::AtomicUsize::new(0);
    let stages = Arc::new(native_byte_diagnostics::Stages::default());
    let _stage_report = native_byte_diagnostics::ReportOnDrop(stages.clone());
    let (tcp, echo) = echo_tcp_native_stages(
        "127.0.0.1".parse().unwrap(),
        uploaded.clone(),
        stages.clone(),
    )
    .await;
    let (udp, udp_echo) = echo_udp("127.0.0.1".parse().unwrap()).await;
    let driver = std::env::var_os("AEGIS_TEST_WINTUN").unwrap();
    let relay_endpoint = cfg.relay.server.parse().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let mut guard = EngineStop {
        stop,
        thread: Some(std::thread::spawn(move || {
            let tun = Wintun::open(
                std::path::Path::new(&driver),
                &format!("AEGIS-E2E-{}", std::process::id()),
            )?;
            let mut net = NetworkGuard::configure(tun.luid, 1280, false)?;
            for route in ["198.18.0.0/16", "198.19.255.2/32", "fd00:ae61::2/128"] {
                net.capture(Prefix::parse(route).map_err(io::Error::other)?)?;
            }
            let luid = tun.luid;
            let mut tun = RecordedPackets::new(tun)?;
            let _ = ready_tx.send(luid);
            run(
                &mut tun,
                cfg.relay,
                thread_stop,
                32,
                Duration::from_secs(60),
                1280,
                "9.9.9.9:53".parse().unwrap(),
            )
        })),
    };
    let luid = tokio::time::timeout(Duration::from_secs(15), ready_rx)
        .await
        .unwrap()
        .unwrap();
    let protection =
        ScopedProtection::install(luid, &std::env::current_exe().unwrap(), &[relay_endpoint])
            .unwrap();
    let work = async {
        eprintln!("native tunnel: UDP DNS");
        // Real applications usually let Windows select the source interface.
        let dns = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        let request = dns_question("127.0.0.1");
        dns.send_to(&request, (ANCHOR_V4, 53)).await.unwrap();
        let mut answer = [0; 1500];
        let n = dns.recv(&mut answer).await.unwrap();
        assert_eq!(&answer[..2], &request[..2]);
        assert_eq!(answer[3] & 15, 0);
        let fake =
            std::net::Ipv4Addr::new(answer[n - 4], answer[n - 3], answer[n - 2], answer[n - 1]);
        assert_eq!(fake.octets()[..2], [198, 18]);
        completed_phases.fetch_add(1, Ordering::Relaxed);
        // TCP DNS over an actual IPv6 application socket tests both native
        // families without altering the machine's ordinary DNS settings.
        eprintln!("native tunnel: IPv6 TCP DNS");
        let mut dns6 = tokio::net::TcpStream::connect((ANCHOR_V6, 53))
            .await
            .unwrap();
        dns6.write_u16(request.len() as u16).await.unwrap();
        dns6.write_all(&request).await.unwrap();
        let size = dns6.read_u16().await.unwrap();
        let mut response = vec![0; size as usize];
        dns6.read_exact(&mut response).await.unwrap();
        assert_eq!(response[n - 4..n], fake.octets());
        eprintln!("native tunnel: large TCP request and half-close response");
        let mut socket = tokio::net::TcpStream::connect((fake, tcp.port()))
            .await
            .unwrap();
        protection
            .reauthorize(luid, &std::env::current_exe().unwrap())
            .unwrap();
        // Exercise the already established IPv6 flow after the same policy
        // change as IPv4, including an inbound response on each address family.
        dns6.write_u16(request.len() as u16).await.unwrap();
        dns6.write_all(&request).await.unwrap();
        let size = dns6.read_u16().await.unwrap();
        let mut response = vec![0; size as usize];
        dns6.read_exact(&mut response).await.unwrap();
        assert_eq!(response[3] & 15, 0);
        assert_eq!(response[n - 4..n], fake.octets());
        drop(dns6);
        completed_phases.fetch_add(1, Ordering::Relaxed);
        let request = payload();
        stages.app_write.store(1, Ordering::Relaxed);
        let result = socket.write_all(&request).await;
        stages
            .app_write
            .store(if result.is_ok() { 2 } else { 3 }, Ordering::Relaxed);
        result.unwrap();
        stages.app_shutdown.store(1, Ordering::Relaxed);
        let result = socket.shutdown().await;
        stages
            .app_shutdown
            .store(if result.is_ok() { 2 } else { 3 }, Ordering::Relaxed);
        result.unwrap();
        let mut response = vec![];
        let mut buffer = [0; 16384];
        loop {
            stages.app_read.store(1, Ordering::Relaxed);
            let result = socket.read(&mut buffer).await;
            stages
                .app_read
                .store(if result.is_ok() { 2 } else { 3 }, Ordering::Relaxed);
            let n = result.unwrap();
            if n == 0 {
                stages.app_eof.store(1, Ordering::Relaxed);
                break;
            }
            stages.app_read_bytes.fetch_add(n, Ordering::Relaxed);
            response.extend_from_slice(&buffer[..n]);
            assert!(
                response.len() <= request.len(),
                "oversized native TCP response"
            );
            downloaded.fetch_add(n, Ordering::Relaxed);
        }
        let comparison = native_byte_diagnostics::Comparison::new(&request, &response);
        assert!(
            comparison.equal,
            "native TCP byte equality mismatch: {comparison:?}"
        );
        completed_phases.fetch_add(1, Ordering::Relaxed);
        // The TCP round can outlive the 60-second DNS answer. Once its lease
        // closes, opening a new flow with that stale synthetic IP must fail.
        // Resolve again, as an application honoring the answer TTL would.
        eprintln!("native tunnel: refresh DNS before new UDP flow");
        let question = dns_question("127.0.0.1");
        dns.send_to(&question, (ANCHOR_V4, 53)).await.unwrap();
        let n = dns.recv(&mut answer).await.unwrap();
        assert!(n >= 16);
        assert_eq!(&answer[..2], &question[..2]);
        assert_eq!(answer[3] & 15, 0);
        let fake =
            std::net::Ipv4Addr::new(answer[n - 4], answer[n - 3], answer[n - 2], answer[n - 1]);
        assert_eq!(fake.octets()[..2], [198, 18]);
        completed_phases.fetch_add(1, Ordering::Relaxed);
        eprintln!("native tunnel: persistent and fragmented UDP");
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
        for i in 0..20u8 {
            let p = vec![i; if i == 0 || i == 3 { 65000 } else { 1200 }];
            socket.send_to(&p, (fake, udp.port())).await.unwrap();
            let mut b = vec![0; 65535];
            let (n, peer) = socket.recv_from(&mut b).await.unwrap();
            assert_eq!(peer, SocketAddr::from((fake, udp.port())));
            assert_eq!(&b[..n], &p);
            completed_phases.fetch_add(1, Ordering::Relaxed);
        }
        eprintln!("native tunnel: all application flows complete");
    };
    tokio::pin!(work);
    let mut deadline = progress_deadline::ProgressDeadline::new(
        Instant::now(),
        Duration::from_secs(45),
        Duration::from_secs(180),
    );
    loop {
        tokio::select! {
            () = &mut work => break,
            () = tokio::time::sleep(Duration::from_millis(200)) => {
                let progress = (
                    uploaded.load(Ordering::Relaxed),
                    downloaded.load(Ordering::Relaxed),
                    completed_phases.load(Ordering::Relaxed),
                );
                assert!(
                    !deadline.expired(Instant::now(), progress),
                    "native full data path stalled or exceeded total bound: uploaded={}, downloaded={}, phases={}",
                    progress.0, progress.1, progress.2,
                );
            }
        }
    }
    guard.stop.store(true, Ordering::Release);
    let stats = guard.thread.take().unwrap().join().unwrap().unwrap();
    assert!(stats.tcp_egress_bytes >= payload().len() as u64);
    assert!(stats.udp_sessions_opened >= 2);
    echo.await.unwrap();
    udp_echo.abort();
    server.abort();
}
