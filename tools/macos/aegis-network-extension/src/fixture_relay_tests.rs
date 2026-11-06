//! B-06 S16b fixture relay, loopback only: its admission checks, and one
//! real composite provider session served end to end until its lifetime.
use super::*;
use crate::{
    provider_session::relay::{
        loopback, production_bridge, recorder, round_trip, runtime, start_armed, times, udp_packet,
    },
    provider_session_body::tests::store_locked,
    test_fixture::{self, ReadyTree},
};
use aegis_client::{packet_engine::services::RelayServices, relay_runtime_types::ConnectTarget};
use aegis_core::{dns_response::is_valid_relay_response, secure_channel::ClientSettings};
use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, KeyPair, KeyUsagePurpose, PKCS_ED25519};
use std::{
    os::unix::fs::{symlink, PermissionsExt},
    thread,
};

/// A private 0700 scratch directory beside, never inside, the App Group
/// fixture: the session's capture admits nothing extra in its root.
struct Scratch(PathBuf);

impl Scratch {
    fn new() -> Self {
        use std::os::unix::fs::DirBuilderExt;
        let path = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "aegis-ne-fixture-relay-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn os(value: &str) -> Option<OsString> {
    Some(value.into())
}

fn dns_query(id: u16, name: &str, qtype: u16, edns: bool) -> Vec<u8> {
    let mut query = id.to_be_bytes().to_vec();
    query.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, u8::from(edns)]);
    for label in name.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&qtype.to_be_bytes());
    query.extend_from_slice(&[0, 1]);
    if edns {
        // OPT: root name, type 41, 4096-byte payload, no options.
        query.extend_from_slice(&[0, 0, 41, 0x10, 0, 0, 0, 0, 0, 0, 0]);
    }
    query
}

fn rcode(response: &[u8]) -> u8 {
    response[3] & 0x0f
}

fn answers(response: &[u8]) -> u16 {
    u16::from_be_bytes([response[6], response[7]])
}

fn open(transport: Transport, host: &str, port: u16) -> OpenRequest {
    OpenRequest {
        version: 1,
        host: host.into(),
        port,
        transport,
    }
}

fn mode(path: &Path, bits: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(bits)).unwrap();
}

#[test]
fn fixture_relay_config_admits_only_one_bounded_unicast_window() {
    let parse = |material: &str, bind: &str, log: &str, seconds: &str| {
        RelayConfig::parse(os(material), os(bind), os(log), os(seconds))
    };
    let good = parse(
        "/m/Aegis.relay",
        "192.168.1.107:443",
        "/l/relay.jsonl",
        "300",
    )
    .unwrap();
    assert_eq!(good.material, PathBuf::from("/m/Aegis.relay"));
    assert_eq!(
        good.bind,
        "192.168.1.107:443".parse::<std::net::SocketAddr>().unwrap()
    );
    assert_eq!(good.log, PathBuf::from("/l/relay.jsonl"));
    assert_eq!(good.lifetime, MAX_LIFETIME);
    assert_eq!(
        parse("/m", "[fd00::7]:443", "/l", "1").unwrap().lifetime,
        Duration::from_secs(1)
    );
    for (material, bind, log, seconds) in [
        ("m/Aegis.relay", "192.168.1.107:443", "/l", "60"),
        ("/m", "192.168.1.107:443", "relay.jsonl", "60"),
        ("/m", "0.0.0.0:443", "/l", "60"),
        ("/m", "[::]:443", "/l", "60"),
        ("/m", "224.0.0.1:443", "/l", "60"),
        ("/m", "255.255.255.255:443", "/l", "60"),
        ("/m", "[::ffff:0.0.0.0]:443", "/l", "60"),
        ("/m", "[::ffff:224.0.0.1]:443", "/l", "60"),
        ("/m", "[::ffff:192.168.1.107]:443", "/l", "60"),
        ("/m", "[ff02::1]:443", "/l", "60"),
        ("/m", "192.168.1.107:0", "/l", "60"),
        ("/m", "192.168.1.107", "/l", "60"),
        ("/m", "relay.test:443", "/l", "60"),
        ("/m", "192.168.1.107:443", "/l", "0"),
        ("/m", "192.168.1.107:443", "/l", "301"),
        ("/m", "192.168.1.107:443", "/l", "1000"),
        ("/m", "192.168.1.107:443", "/l", "+5"),
        ("/m", "192.168.1.107:443", "/l", " 5"),
        ("/m", "192.168.1.107:443", "/l", ""),
        ("/m", "192.168.1.107:443", "/l", "5s"),
    ] {
        assert!(
            parse(material, bind, log, seconds).is_err(),
            "admitted {material} {bind} {log} {seconds}"
        );
    }
    for missing in 0..4 {
        let mut values = [os("/m"), os("192.168.1.107:443"), os("/l"), os("60")];
        values[missing] = None;
        let [material, bind, log, seconds] = values;
        assert!(RelayConfig::parse(material, bind, log, seconds).is_err());
    }
}

#[test]
fn fixture_relay_routes_only_the_probe_targets() {
    use Transport::{Tcp, Udp};
    for (transport, host, port, expected) in [
        (Tcp, "192.0.2.10", 7, Route::TcpEcho),
        (Tcp, "2001:db8::10", 7, Route::TcpEcho),
        (Tcp, "[2001:db8::10]", 7, Route::TcpEcho),
        (Tcp, "probe.test", 7, Route::TcpEcho),
        (Tcp, "PROBE.test.", 7, Route::TcpEcho),
        (Udp, "192.0.2.10", 7, Route::UdpEcho),
        (Udp, "2001:db8::10", 7, Route::UdpEcho),
        (Udp, "198.19.255.2", 53, Route::DnsUdp),
        (Tcp, "198.19.255.2", 53, Route::DnsTcp),
        // Everything else is refused.
        (Udp, "probe.test", 7, Route::Refused),
        (Tcp, "probe.test", 8, Route::Refused),
        (Tcp, "probe.test.evil", 7, Route::Refused),
        (Tcp, "xprobe.test", 7, Route::Refused),
        (Tcp, "192.0.2.10", 8, Route::Refused),
        (Tcp, "192.0.2.11", 7, Route::Refused),
        (Udp, "2001:db8::11", 7, Route::Refused),
        (Tcp, "::ffff:192.0.2.10", 7, Route::Refused),
        (Udp, "198.19.255.2", 54, Route::Refused),
        (Udp, "198.19.255.3", 53, Route::Refused),
        (Tcp, "fd00:ae61::2", 53, Route::Refused),
        (Tcp, "example.com", 443, Route::Refused),
        (Tcp, "192.168.1.107", 443, Route::Refused),
    ] {
        assert_eq!(
            route(&open(transport, host, port)),
            expected,
            "{transport:?} {host}:{port}"
        );
    }
}

#[test]
fn fixture_relay_dns_answers_probe_txt_and_aaaa_and_refuses_other_names() {
    for edns in [false, true] {
        let txt = dns_query(0x1601, "probe.test", 16, edns);
        let reply = probe_dns_answer(&txt).unwrap();
        assert_eq!((reply.qtype, reply.outcome), (16, "answered"));
        assert!(is_valid_relay_response(&txt, &reply.response));
        assert_eq!((rcode(&reply.response), answers(&reply.response)), (0, 1));
        let mut rdata = vec![PROBE_TXT.len() as u8];
        rdata.extend_from_slice(PROBE_TXT);
        assert!(reply.response.ends_with(&rdata));
        // RD preserved, QR and RA set, no additional records returned.
        assert_eq!(reply.response[2], 0x81);
        assert_eq!(reply.response[3], 0x80);
        assert_eq!(&reply.response[8..12], &[0, 0, 0, 0]);

        let aaaa = dns_query(0x1602, "Probe.Test", 28, edns);
        let reply = probe_dns_answer(&aaaa).unwrap();
        assert!(is_valid_relay_response(&aaaa, &reply.response));
        assert_eq!((rcode(&reply.response), answers(&reply.response)), (0, 1));
        assert!(reply.response.ends_with(&PROBE_AAAA.octets()));

        let https = dns_query(0x1603, "probe.test", 65, edns);
        let reply = probe_dns_answer(&https).unwrap();
        assert_eq!(reply.outcome, "nodata");
        assert!(is_valid_relay_response(&https, &reply.response));
        assert_eq!((rcode(&reply.response), answers(&reply.response)), (0, 0));

        for name in ["other.test", "probe.test.evil", "test", "xprobe.test"] {
            let query = dns_query(0x1604, name, 28, edns);
            let reply = probe_dns_answer(&query).unwrap();
            assert_eq!(reply.outcome, "refused_name", "{name}");
            assert!(is_valid_relay_response(&query, &reply.response));
            assert_eq!((rcode(&reply.response), answers(&reply.response)), (5, 0));
        }
    }
    // A non-IN class is refused too.
    let mut chaos = dns_query(0x1605, "probe.test", 16, false);
    let class = chaos.len() - 1;
    chaos[class] = 3;
    assert_eq!(rcode(&probe_dns_answer(&chaos).unwrap().response), 5);
    // Malformed queries and responses get nothing.
    let good = dns_query(0x1606, "probe.test", 16, false);
    let mut response = good.clone();
    response[2] |= 0x80;
    let mut opcode = good.clone();
    opcode[2] |= 0x10;
    let mut two = good.clone();
    two[5] = 2;
    let mut pointer = good[..12].to_vec();
    pointer.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1]);
    for malformed in [
        &good[..11],
        &good[..good.len() - 1],
        &response[..],
        &opcode[..],
        &two[..],
        &pointer[..],
        &vec![0; MAX_DNS_MESSAGE + 1][..],
    ] {
        assert_eq!(probe_dns_answer(malformed), None);
    }
}

#[test]
fn fixture_relay_material_reader_admits_only_the_private_five_leaves() {
    let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
    let dir = tree.root().join("Aegis.relay");
    tree.write_relay_material(&dir);
    FixtureIdentity::new(FixtureMaterial::read(&dir).unwrap()).unwrap();
    let refused = |path: &Path| FixtureMaterial::read(path).err().map(|error| error.kind());

    assert_eq!(
        refused(Path::new("Aegis.relay")),
        Some(io::ErrorKind::InvalidInput)
    );
    let key = dir.join("inner-server.key");
    mode(&key, 0o640);
    assert_eq!(refused(&dir), Some(io::ErrorKind::PermissionDenied));
    mode(&key, 0o600);
    mode(&dir, 0o750);
    assert_eq!(refused(&dir), Some(io::ErrorKind::PermissionDenied));
    mode(&dir, 0o700);
    // Exactly the five leaves: an extra or a missing one is refused.
    let extra = dir.join("device.pem");
    fs::write(&extra, b"public").unwrap();
    mode(&extra, 0o600);
    assert_eq!(refused(&dir), Some(io::ErrorKind::InvalidInput));
    fs::remove_file(&extra).unwrap();
    let ca = dir.join("device-ca.pem");
    let aside = tree.root().join("device-ca.pem.aside");
    fs::rename(&ca, &aside).unwrap();
    assert_eq!(refused(&dir), Some(io::ErrorKind::InvalidInput));
    // A symlinked leaf is not followed; a symlinked directory is refused.
    symlink(&aside, &ca).unwrap();
    assert!(refused(&dir).is_some());
    fs::remove_file(&ca).unwrap();
    fs::rename(&aside, &ca).unwrap();
    let link = tree.root().join("relay-link");
    symlink(&dir, &link).unwrap();
    assert_eq!(refused(&link), Some(io::ErrorKind::PermissionDenied));
    // An oversized leaf is refused even when its PEM would still parse.
    let outer = dir.join("outer-server.pem");
    let outer_pem = fs::read(&outer).unwrap();
    let mut padded = outer_pem.clone();
    padded.resize(MAX_MATERIAL_BYTES as usize, b'\n');
    fs::write(&outer, &padded).unwrap();
    FixtureMaterial::read(&dir).unwrap();
    padded.push(b'\n');
    fs::write(&outer, &padded).unwrap();
    assert_eq!(refused(&dir), Some(io::ErrorKind::InvalidInput));
    fs::write(&outer, &outer_pem).unwrap();
    // A leaf that is not what its name says.
    let saved = fs::read(&ca).unwrap();
    fs::write(&ca, fs::read(dir.join("outer-server.pem")).unwrap()).unwrap();
    assert_eq!(refused(&dir), Some(io::ErrorKind::InvalidInput));
    fs::write(&ca, &saved).unwrap();
    FixtureMaterial::read(&dir).unwrap();
}

#[test]
fn fixture_relay_log_is_fresh_private_and_one_object_per_line() {
    let tree = ReadyTree::new("127.0.0.1:443".parse().unwrap());
    assert!(JsonLog::create(Path::new("relay.jsonl")).is_err());
    let path = tree.root().join("relay.jsonl");
    let log = JsonLog::create(&path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o600);
    assert_eq!(
        JsonLog::create(&path).err().map(|error| error.kind()),
        Some(io::ErrorKind::AlreadyExists)
    );
    let link = tree.root().join("relay-link.jsonl");
    symlink(tree.root().join("absent.jsonl"), &link).unwrap();
    assert!(JsonLog::create(&link).is_err());
    assert!(!tree.root().join("absent.jsonl").exists());
    log.event("probe", json!({"conn": 3, "host": "probe.test"}));
    log.event("stop", Value::Null);
    let text = fs::read_to_string(&path).unwrap();
    let lines: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0]["event"], "probe");
    assert_eq!(lines[0]["conn"], 3);
    assert_eq!(lines[0]["host"], "probe.test");
    assert!(lines[0]["t_ms"].is_u64() && lines[0]["unix_ms"].as_u64().unwrap() > 0);
    assert_eq!(lines[1]["event"], "stop");
}

struct Device {
    cert_pem: String,
    key_pem: String,
    sha256: String,
    not_after: u64,
}

fn issue(ca: &rcgen::Certificate, ca_key: &KeyPair, device_id: &str) -> Device {
    let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let key_pem = key.serialize_pem();
    let csr = enrollment::csr_for_key(device_id, &key_pem).unwrap();
    let issued = enrollment::sign_csr(
        device_id,
        &csr,
        &ca.pem(),
        &ca_key.serialize_pem(),
        registry::unix_now().unwrap(),
        3_600,
    )
    .unwrap();
    Device {
        cert_pem: issued.certificate_pem,
        key_pem,
        sha256: issued.record.certificate_sha256,
        not_after: issued.record.not_after_unix_secs,
    }
}

#[test]
fn fixture_relay_device_gate_pins_the_first_fixture_device_and_refuses_others() {
    let (inner_ca, inner_ca_key) = test_fixture::signing_ca();
    let mut params = CertificateParams::new(vec!["inner.test".into()]).unwrap();
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let inner_key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
    let inner = params
        .signed_by(&inner_key, &inner_ca, &inner_ca_key)
        .unwrap();
    let outer = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let (device_ca, device_ca_key) = test_fixture::signing_ca();
    let (other_ca, other_ca_key) = test_fixture::signing_ca();
    let identity = FixtureIdentity::new(
        FixtureMaterial::from_pem(
            outer.cert.pem().as_bytes(),
            outer.key_pair.serialize_pem().as_bytes(),
            inner.pem().as_bytes(),
            inner_key.serialize_pem().as_bytes(),
            device_ca.pem().as_bytes(),
        )
        .unwrap(),
    )
    .unwrap();
    let first = issue(&device_ca, &device_ca_key, test_fixture::DEVICE_ID);
    let second = issue(&device_ca, &device_ca_key, test_fixture::DEVICE_ID);
    let renamed = issue(&device_ca, &device_ca_key, "fixture-device-2");
    let foreign = issue(&other_ca, &other_ca_key, test_fixture::DEVICE_ID);
    let settings = ClientSettings {
        server_name: "inner.test".into(),
        server_ca: PathBuf::new(),
        cert: PathBuf::new(),
        key: PathBuf::new(),
    };
    let runtime = runtime();
    let admit = |device: &Device| {
        let client = secure_channel::Client::from_captured_pem(
            &settings,
            inner_ca.pem().as_bytes(),
            device.cert_pem.as_bytes(),
            device.key_pem.as_bytes(),
        )
        .unwrap();
        runtime.block_on(async {
            let (client_side, relay_side) = tokio::io::duplex(64 * 1024);
            let (_client, relay) = tokio::join!(
                client.connect(client_side),
                identity.accept_device(relay_side)
            );
            relay.map(|(_, device, pinned)| (device, pinned))
        })
    };
    let expected = AdmittedDevice {
        certificate_sha256: first.sha256.clone(),
        not_after_unix_secs: first.not_after,
    };
    // The leaf the relay saw is the issued certificate, byte for byte.
    let der = CertificateDer::from_pem_slice(first.cert_pem.as_bytes()).unwrap();
    assert_eq!(
        CertificateDer::from_pem_slice(certificate_pem(der.as_ref()).as_bytes()).unwrap(),
        der
    );
    assert_eq!(admit(&first), Ok((expected.clone(), true)));
    assert_eq!(admit(&first), Ok((expected.clone(), false)));
    assert_eq!(admit(&second), Err("device_pin_mismatch"));
    assert_eq!(admit(&renamed), Err("device_profile_refused"));
    assert_eq!(admit(&foreign), Err("inner_tls_refused"));
    assert_eq!(admit(&first), Ok((expected.clone(), false)));
    // The ACK names the admitted device and the fixture issuance at 3 s.
    let reply = expected.reply(1_000);
    assert_eq!(reply.certificate_sha256, first.sha256);
    assert_eq!(reply.certificate_not_after_unix_secs, first.not_after);
    assert_eq!(reply.generation, test_fixture::ISSUED_GENERATION);
    assert_eq!(reply.snapshot_sha256, test_fixture::SNAPSHOT_SHA256);
    assert_eq!(reply.effective_valid_for_ms, MAX_ACK_VALID_MS);
    assert_eq!(reply.policy_not_after_unix_secs, 1_060);
}

fn log_events(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn count(events: &[Value], event: &str, field: &str, value: &str) -> usize {
    events
        .iter()
        .filter(|line| line["event"] == event && (field.is_empty() || line[field] == value))
        .count()
}

#[test]
fn fixture_relay_stop_closes_live_connections_at_once() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let tree = ReadyTree::new(address);
    let dir = tree.root().join("Aegis.relay");
    tree.write_relay_material(&dir);
    let log_path = tree.root().join("relay.jsonl");
    // An out-of-range lifetime is refused before anything is created.
    let unused = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let material = FixtureMaterial::read(&dir).unwrap();
    let pending = std::future::pending::<&'static str>();
    assert!(serve(
        unused,
        material,
        &log_path,
        MAX_LIFETIME + Duration::from_secs(1),
        pending
    )
    .is_err());
    assert!(!log_path.exists());

    let material = FixtureMaterial::read(&dir).unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let relay = {
        let log_path = log_path.clone();
        thread::spawn(move || {
            serve(listener, material, &log_path, MAX_LIFETIME, async move {
                let _ = stopped.await;
                "sigterm"
            })
        })
    };
    // Two connections that never finish outer TLS stay live in the relay.
    let mut held: Vec<_> = (0..2)
        .map(|_| std::net::TcpStream::connect(address).unwrap())
        .collect();
    let deadline = Instant::now() + Duration::from_secs(2);
    while !log_path.exists() || count(&log_events(&log_path), "accepted", "", "") < 2 {
        assert!(Instant::now() < deadline, "connections never accepted");
        thread::sleep(Duration::from_millis(5));
    }
    let asked = Instant::now();
    stop.send(()).unwrap();
    while !relay.is_finished() {
        assert!(
            asked.elapsed() < Duration::from_secs(3),
            "relay ignored its stop"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let summary = relay.join().unwrap().unwrap();
    assert!(
        asked.elapsed() < Duration::from_secs(1),
        "{:?}",
        asked.elapsed()
    );
    assert_eq!(summary.reason, "sigterm");
    assert_eq!((summary.connections, summary.aborted), (2, 2));
    assert_eq!((summary.acks, summary.opens), (0, 0));
    for stream in &mut held {
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut byte = [0; 1];
        match stream.read(&mut byte) {
            Ok(read) => assert_eq!(read, 0),
            Err(error) => assert!(
                !matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ),
                "connection left open: {error}"
            ),
        }
    }
    let events = log_events(&log_path);
    assert_eq!(events[0]["event"], "relay_started");
    assert_eq!(count(&events, "stop", "reason", "sigterm"), 1);
    let last = events.last().unwrap();
    assert_eq!(last["event"], "all_flows_closed");
    assert_eq!(last["aborted"], 2);
    // The listener is gone with the window.
    assert!(std::net::TcpStream::connect_timeout(&address, Duration::from_millis(300)).is_err());
}

/// One TCP echo flow through the session's relay services; returns the app
/// side and the flow once `payload` came back.
async fn echo_flow(
    services: &Arc<crate::held_relay_services::HeldRelayServices>,
    host: &str,
    payload: &[u8],
) -> (TcpStream, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let (mut app, local) = loopback().await;
    let flow = {
        let services = services.clone();
        let settings = services.signed_relay();
        let host = host.to_owned();
        tokio::spawn(async move { services.tcp(local, &settings, host, 7).await })
    };
    app.write_all(payload).await.unwrap();
    let mut echoed = vec![0; payload.len()];
    tokio::time::timeout(Duration::from_secs(2), app.read_exact(&mut echoed))
        .await
        .unwrap_or_else(|_| panic!("no echo from {host}"))
        .unwrap();
    assert_eq!(echoed, payload);
    (app, flow)
}

async fn close_flow(mut app: TcpStream, flow: tokio::task::JoinHandle<anyhow::Result<()>>) {
    app.shutdown().await.unwrap();
    let mut rest = Vec::new();
    app.read_to_end(&mut rest).await.unwrap();
    assert!(rest.is_empty());
    flow.await.unwrap().unwrap();
}

/// One DNS query over TCP to the signed upstream, as the engine forwards a
/// non-A TCP query.
async fn tcp_dns(
    services: &Arc<crate::held_relay_services::HeldRelayServices>,
    query: &[u8],
) -> Vec<u8> {
    let (mut app, local) = loopback().await;
    let upstream = dns_upstream();
    let flow = {
        let services = services.clone();
        let settings = services.signed_relay();
        tokio::spawn(async move {
            services
                .tcp(local, &settings, upstream.ip().to_string(), upstream.port())
                .await
        })
    };
    app.write_u16(query.len() as u16).await.unwrap();
    app.write_all(query).await.unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), async {
        let length = app.read_u16().await?;
        let mut response = vec![0; usize::from(length)];
        app.read_exact(&mut response).await?;
        io::Result::Ok(response)
    })
    .await
    .expect("no TCP DNS answer")
    .unwrap();
    close_flow(app, flow).await;
    response
}

#[test]
fn fixture_relay_serves_a_provider_session_end_to_end_until_its_lifetime() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let tree = ReadyTree::with_online_completed(listener.local_addr().unwrap());
    let scratch = Scratch::new();
    let material_dir = scratch.0.join("Aegis.relay");
    tree.write_relay_material(&material_dir);
    let material = FixtureMaterial::read(&material_dir).unwrap();
    let log_path = scratch.0.join("relay.jsonl");
    // Every flow below and the first re-ACK are done within about 1 s of
    // the start on loopback (S16n: measured 0.2 s and 0.9 s): 4 s keeps the
    // held flow open across a re-ACK, then ends the window on the clock.
    let lifetime = Duration::from_secs(4);
    let started = Instant::now();
    let relay = {
        let log_path = log_path.clone();
        thread::spawn(move || {
            serve(
                listener,
                material,
                &log_path,
                lifetime,
                std::future::pending(),
            )
        })
    };
    let (trace, steps) = recorder();
    let (mut session, _phases, (services, gate)) = start_armed(&tree, production_bridge(), trace);
    let probe = session.probe();
    let bridge = probe.bridge();

    // UDP echo for both targets, through packetFlow's side of the bridge.
    let app4: SocketAddr = "198.19.0.10:40000".parse().unwrap();
    let app6: SocketAddr = "[fd00:ae61::10]:40001".parse().unwrap();
    for (app, target) in [(app4, ECHO_V4), (app6, ECHO_V6)] {
        let payload = format!("udp echo {target}");
        let packet = udp_packet(app, target, payload.as_bytes());
        assert_eq!(round_trip(bridge, &packet, target, app), payload.as_bytes());
    }
    // Non-A queries to the tunnel resolver reach the signed upstream.
    let resolver = dns_upstream();
    let txt = dns_query(0x5161, PROBE_NAME, 16, false);
    let answer = round_trip(bridge, &udp_packet(app4, resolver, &txt), resolver, app4);
    assert!(is_valid_relay_response(&txt, &answer));
    assert_eq!((rcode(&answer), answers(&answer)), (0, 1));
    assert!(answer.ends_with(PROBE_TXT));
    let aaaa = dns_query(0x5162, PROBE_NAME, 28, false);
    let answer = round_trip(bridge, &udp_packet(app4, resolver, &aaaa), resolver, app4);
    assert!(is_valid_relay_response(&aaaa, &answer));
    assert!(answer.ends_with(&PROBE_AAAA.octets()));
    let other = dns_query(0x5163, "other.test", 28, false);
    let answer = round_trip(bridge, &udp_packet(app4, resolver, &other), resolver, app4);
    assert_eq!((rcode(&answer), answers(&answer)), (5, 0));

    let runtime = runtime();
    let (held_app, held_flow) = runtime.block_on(async {
        // TCP echo: IPv4, IPv6 and the hostname a fake-IP connection names.
        let held = echo_flow(&services, "192.0.2.10", b"held across re-ACKs").await;
        for host in ["2001:db8::10", PROBE_NAME] {
            let (app, flow) = echo_flow(&services, host, host.as_bytes()).await;
            close_flow(app, flow).await;
        }
        // DNS over TCP.
        let answer = tcp_dns(&services, &txt).await;
        assert!(is_valid_relay_response(&txt, &answer));
        assert!(answer.ends_with(PROBE_TXT));
        let answer = tcp_dns(&services, &aaaa).await;
        assert!(is_valid_relay_response(&aaaa, &answer));
        assert!(answer.ends_with(&PROBE_AAAA.octets()));
        // Every other target is refused at once, never left hanging.
        let settings = services.signed_relay();
        for (host, port) in [
            ("203.0.113.9", 80),
            ("example.com", 443),
            ("192.0.2.10", 8),
            ("probe.test", 8),
        ] {
            let (_app, local) = loopback().await;
            let asked = Instant::now();
            let result = services.tcp(local, &settings, host.into(), port).await;
            assert!(result.is_err(), "{host}:{port} was served");
            assert!(asked.elapsed() < Duration::from_secs(1), "{host}:{port}");
        }
        for (host, port) in [("203.0.113.9", 53), (PROBE_NAME, 7)] {
            let target = ConnectTarget {
                host: host.into(),
                port,
            };
            let asked = Instant::now();
            let result = services.udp_once(&settings, target, b"probe").await;
            assert!(result.is_err(), "udp {host}:{port} was served");
            assert!(
                asked.elapsed() < Duration::from_secs(1),
                "udp {host}:{port}"
            );
        }
        held
    });
    // The session keeps re-ACKing on fresh connections.
    let deadline = Instant::now() + Duration::from_secs(4);
    while times(&steps, "reack_renewed").is_empty() {
        assert!(Instant::now() < deadline, "no re-ACK was served");
        thread::sleep(Duration::from_millis(10));
    }

    // The window ends at its lifetime and closes the held flow with it.
    let deadline = started + lifetime + Duration::from_secs(3);
    while !relay.is_finished() {
        assert!(Instant::now() < deadline, "relay outlived its lifetime");
        thread::sleep(Duration::from_millis(10));
    }
    let summary = relay.join().unwrap().unwrap();
    let ended = started.elapsed();
    assert!(
        ended >= lifetime && ended <= lifetime + Duration::from_secs(3),
        "relay ended after {ended:?}"
    );
    let closed_after = Instant::now();
    runtime.block_on(async {
        let mut held_app = held_app;
        let mut byte = [0; 1];
        let read = tokio::time::timeout(Duration::from_secs(1), held_app.read(&mut byte))
            .await
            .expect("held flow outlived the relay");
        assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
        let flow = tokio::time::timeout(Duration::from_secs(1), held_flow)
            .await
            .expect("held flow task outlived the relay")
            .unwrap();
        assert!(flow.is_err());
    });
    assert!(closed_after.elapsed() < Duration::from_secs(2));
    assert_eq!(summary.reason, "lifetime_reached");
    assert!(summary.acks >= 2, "{summary:?}");
    assert_eq!(summary.refused, 6, "{summary:?}");
    // S16h: flows are streams of pooled connections, so the window served
    // fewer connections than ACKs and Opens.
    assert!(
        summary.connections < summary.acks + summary.opens,
        "{summary:?}"
    );
    assert!(summary.aborted >= 1, "{summary:?}");

    let events = log_events(&log_path);
    assert_eq!(events[0]["event"], "relay_started");
    assert_eq!(events.last().unwrap()["event"], "all_flows_closed");
    assert_eq!(count(&events, "stop", "reason", "lifetime_reached"), 1);
    assert_eq!(count(&events, "device_pinned", "", ""), 1);
    let pinned = events
        .iter()
        .find(|line| line["event"] == "device_pinned")
        .unwrap();
    assert_eq!(
        pinned["certificate_sha256"],
        tree.online().certificate_sha256
    );
    assert_eq!(
        pinned["not_after_unix_secs"],
        tree.online().not_after_unix_secs
    );
    assert_eq!(count(&events, "device_refused", "", ""), 0);
    assert_eq!(count(&events, "ack", "", "") as u64, summary.acks);
    assert_eq!(count(&events, "open", "outcome", "tcp_echo"), 3);
    assert!(count(&events, "open", "outcome", "udp_echo") >= 2);
    assert!(count(&events, "open", "outcome", "dns_udp") >= 3);
    assert_eq!(count(&events, "open", "outcome", "dns_tcp"), 2);
    assert_eq!(count(&events, "open", "outcome", "refused"), 6);
    for host in ["203.0.113.9", "example.com"] {
        assert!(events.iter().any(|line| line["event"] == "open"
            && line["host"] == host
            && line["outcome"] == "refused"));
    }
    assert!(count(&events, "dns", "outcome", "answered") >= 4);
    assert!(count(&events, "dns", "outcome", "refused_name") >= 1);
    // Both TCP echoes and both TCP DNS flows end on the app's EOF; the
    // engine drops a udp_once channel once it has its answer.
    assert_eq!(count(&events, "flow_end", "end", "eof"), 4);
    // Every accepted connection was either closed or aborted at the end.
    assert_eq!(
        count(&events, "close", "", "") + summary.aborted,
        count(&events, "accepted", "", "")
    );
    assert_eq!(
        count(&events, "accepted", "", "") as u64,
        summary.connections
    );
    // No key material reaches the log.
    let text = fs::read_to_string(&log_path).unwrap();
    assert!(!text.contains("PRIVATE KEY"));
    for leaf in ["outer-server.key", "inner-server.key"] {
        let pem = fs::read_to_string(material_dir.join(leaf)).unwrap();
        for line in pem.lines().filter(|line| !line.starts_with("-----")) {
            assert!(!text.contains(line), "{leaf} line logged");
        }
    }
    assert_eq!(fs::metadata(&log_path).unwrap().mode() & 0o7777, 0o600);

    assert!(session.try_join(Duration::from_secs(2)));
    assert!(gate.drained());
    assert!(!store_locked(&tree.identity_dir()));
}
