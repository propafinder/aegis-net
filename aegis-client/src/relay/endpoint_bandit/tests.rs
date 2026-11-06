use super::*;
use aegis_core::{RelayEndpointSettings, Settings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

struct Task(tokio::task::JoinHandle<()>);
impl Drop for Task {
    fn drop(&mut self) {
        self.0.abort();
    }
}
fn config() -> RelayEndpointBanditSettings {
    RelayEndpointBanditSettings {
        algorithm: aegis_core::brain::recent_routes::paper_bandit::PaperAlgorithm::SlidingWindow {
            rounds: 16,
            xi: 1.0,
        },
        max_profiles: 16,
        max_contexts_per_profile: 16,
        pre_auth_block_ms: 1000,
        dependency_policy: None,
    }
}
fn pin(address: std::net::SocketAddr) -> RelayEndpointSettings {
    RelayEndpointSettings {
        server: address.to_string(),
        server_name: "localhost".into(),
        masque_server: None,
        masque_server_name: None,
    }
}
async fn pool(dir: &std::path::Path) -> (Settings, Vec<Task>) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let a = first.local_addr().unwrap();
    let b = second.local_addr().unwrap();
    let (mut settings, mut server) = super::super::secure::tests::configs(dir, &a.to_string());
    let shape = aegis_core::carrier_runtime::PrivacySettings {
        payload_bytes: 4096,
        cadence_ms: 1,
        buffer_bytes: 16384,
        max_wire_bytes: 67108864,
        io_timeout_ms: 250,
        session_timeout_ms: 30000,
        max_queue_delay_ms: 2000,
        poisson_pacing: None,
        net_shaper: None,
        adaptive_channel: None,
        arrival_envelope: None,
        cover_stream: None,
        bit_traps: None,
        liu_channel: None,
    };
    settings.relay.authenticated_shaping = Some(shape.clone());
    server.transport.authenticated_shaping = Some(shape);
    settings.relay.auth_token.clear();
    settings.relay.endpoint_bandit = Some(config());
    settings.relay.endpoints = vec![pin(a), pin(b)];
    drop(first);
    drop(second);
    let mut tasks = Vec::new();
    for address in [a, b] {
        let mut server = server.clone();
        server.listen = address.to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tasks.push(Task(tokio::spawn(async move {
            aegis_server::run_server_with_shutdown(server, Some(tx), std::future::pending::<()>())
                .await
                .unwrap();
        })));
        tokio::time::timeout(Duration::from_secs(5), rx)
            .await
            .unwrap()
            .unwrap();
    }
    (settings, tasks)
}
async fn exchange(settings: &RelaySettings, target: &TcpListener) {
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    let flow = super::super::run_relay_tunnel(
        client,
        settings,
        "127.0.0.1".into(),
        target.local_addr().unwrap().port(),
        None,
        None,
        None,
    );
    let application = async {
        app.write_all(b"ping").await.unwrap();
        app.shutdown().await.unwrap();
        let mut reply = Vec::new();
        app.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"pong");
    };
    let destination = async {
        let (mut socket, _) = target.accept().await.unwrap();
        let mut data = Vec::new();
        socket.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"ping");
        socket.write_all(b"pong").await.unwrap();
        socket.shutdown().await.unwrap();
    };
    tokio::time::timeout(Duration::from_secs(10), async {
        let (result, (), ()) = tokio::join!(flow, application, destination);
        result.unwrap();
    })
    .await
    .unwrap();
}
fn stats(selection: &Selection) -> Vec<(usize, f64)> {
    let state = selection.state.lock().unwrap();
    (0..selection.pool.len())
        .map(|i| {
            let e = state.estimator.estimate(&format!("{i:02}"));
            (e.trials, e.mean)
        })
        .collect()
}

#[tokio::test]
async fn two_real_endpoints_learn_progress_explore_and_adapt_to_pre_auth_outage() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, mut servers) = pool(directory.path()).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let selection = prepare(&settings.relay, "127.0.0.1", port, "tcp")
        .unwrap()
        .unwrap();
    assert_eq!(stats(&selection), vec![(0, 0.0), (0, 0.0)]);
    exchange(&settings.relay, &target).await;
    assert_eq!(stats(&selection), vec![(1, 1.0), (0, 0.0)]);
    assert_eq!(
        selection.rank(selection.pool.clone()).unwrap()[0].server,
        settings.relay.endpoints[1].server
    );
    exchange(&settings.relay, &target).await;
    assert_eq!(stats(&selection), vec![(1, 1.0), (1, 1.0)]);
    servers[0].0.abort();
    (&mut servers[0].0).await.unwrap_err();
    exchange(&settings.relay, &target).await;
    assert_eq!(stats(&selection), vec![(2, 0.5), (2, 1.0)]);
    assert_eq!(
        selection.rank(selection.pool.clone()).unwrap()[0].server,
        settings.relay.endpoints[1].server
    );
}

#[tokio::test]
async fn authenticated_failure_is_terminal_without_target_or_backup_replay() {
    let directory = tempfile::tempdir().unwrap();
    let (mut settings, _servers) = pool(directory.path()).await;
    // Existing numeric backup is observable but never opened after fatal inner authentication.
    let backup = TcpListener::bind("127.0.0.1:0").await.unwrap();
    settings.relay.endpoints[1] = pin(backup.local_addr().unwrap());
    settings.relay.inner_tls.as_mut().unwrap().server_name = "wrong-inner.test".into();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let selection = prepare(&settings.relay, "127.0.0.1", port, "tcp")
        .unwrap()
        .unwrap();
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    let result = super::super::run_relay_tunnel(
        client,
        &settings.relay,
        "127.0.0.1".into(),
        port,
        Some(b"never replay"),
        None,
        None,
    );
    assert!(tokio::time::timeout(Duration::from_secs(5), result)
        .await
        .unwrap()
        .is_err());
    assert_eq!(stats(&selection), vec![(1, 0.0), (0, 0.0)]);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backup.accept())
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
}

#[test]
fn opt_out_has_no_certificate_io_or_registry_admission() {
    let settings = RelaySettings {
        ca_cert: Some("/missing/unreadable/ca".into()),
        ..Default::default()
    };
    assert!(prepare(&settings, "test", 443, "tcp").unwrap().is_none());
}
#[tokio::test]
async fn trust_order_shape_context_and_hard_eligibility_are_bound() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, _servers) = pool(directory.path()).await;
    let first = prepare(&settings.relay, "same", 443, "tcp")
        .unwrap()
        .unwrap();
    first
        .attempt(&first.pool[0].server)
        .unwrap()
        .unwrap()
        .progress();
    let mut reorder = settings.relay.clone();
    reorder.endpoints.swap(0, 1);
    reorder.server = reorder.endpoints[0].server.clone();
    let fresh = prepare(&reorder, "same", 443, "tcp").unwrap().unwrap();
    assert_eq!(stats(&fresh), vec![(0, 0.0), (0, 0.0)]);
    let different = prepare(&settings.relay, "same", 443, "udp")
        .unwrap()
        .unwrap();
    assert_eq!(stats(&different), vec![(0, 0.0), (0, 0.0)]);
    let mut foreign = first.pool[0].clone();
    foreign.server_name = "foreign.test".into();
    assert!(first.rank(vec![foreign]).is_err());
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(settings.relay.ca_cert.as_ref().unwrap(), cert.cert.pem()).unwrap();
    let ticket = first.attempt(&first.pool[0].server).unwrap().unwrap();
    assert!(ticket.validate_after_open().is_err());
    let rotated = prepare(&settings.relay, "same", 443, "tcp")
        .unwrap()
        .unwrap();
    assert_eq!(stats(&rotated), vec![(0, 0.0), (0, 0.0)]);
}
#[test]
fn numeric_pool_authority_and_policy_limits_refuse_before_io() {
    let settings = RelaySettings {
        endpoint_bandit: Some(config()),
        ..Default::default()
    };
    assert!(settings.validate_inner_tls_transport().is_err());
    assert!(serde_json::from_str::<RelayEndpointBanditSettings>(r#"{"algorithm":{"algorithm":"sliding_window","rounds":16,"xi":1.0},"max_profiles":16,"max_contexts_per_profile":16,"pre_auth_block_ms":1,"key":"secret"}"#).is_err());
}

#[test]
fn endpoint_registry_live_caps_refuse_without_eviction_or_partial_new_profile() {
    let mut registry = Registry::default();
    let mut policy = config();
    policy.max_profiles = 1;
    let first = registry.admit([0; 32], [0; 32], &policy).unwrap();
    assert!(registry.admit([1; 32], [0; 32], &policy).is_err());
    assert_eq!(registry.profiles.len(), 1);
    policy.max_contexts_per_profile = 1;
    assert!(registry.admit([0; 32], [1; 32], &policy).is_err());
    assert!(Arc::ptr_eq(
        &first,
        &registry.admit([0; 32], [0; 32], &policy).unwrap()
    ));
    let mut registry = Registry::default();
    policy.max_profiles = 16;
    policy.max_contexts_per_profile = 64;
    let mut held = Vec::new();
    for i in 0..64 {
        held.push(registry.admit([0; 32], [i; 32], &policy).unwrap());
    }
    assert!(registry.admit([1; 32], [0; 32], &policy).is_err());
    assert_eq!(registry.profiles.len(), 1);
    assert_eq!(registry.profiles[&[0; 32]].len(), 64);
}
#[tokio::test]
async fn exhausted_original_deadline_refuses_before_private_identity_and_dial() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, _servers) = pool(directory.path()).await;
    let selection = prepare(&settings.relay, "target.test", 443, "tcp")
        .unwrap()
        .unwrap();
    let mut ticket = selection
        .attempt(&selection.pool[0].server)
        .unwrap()
        .unwrap();
    ticket.deadline = tokio::time::Instant::now();
    let mut selected =
        super::super::relay_settings_for_endpoint(&settings.relay, &selection.pool[0]);
    selected.inner_tls.as_mut().unwrap().key = directory.path().join("does-not-exist.key");
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _app = TcpStream::connect(listener.local_addr().unwrap())
        .await
        .unwrap();
    let (mut local, _) = listener.accept().await.unwrap();
    let counters = super::super::RelaySessionCounters::default();
    let error = super::super::secure::run_with_endpoint(
        &mut local,
        &selected,
        "target.test".into(),
        443,
        None,
        &counters,
        Some(&ticket),
        None,
        None,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("before identity access"));
    assert!(!counters.was_opened());
}
#[test]
fn valid_policy_rejects_dns_duplicate_masque_bad_authority_and_bounds_before_io() {
    let mut relay = RelaySettings::default();
    relay.auth_token.clear();
    relay.server = "127.0.0.1:443".into();
    relay.server_name = "localhost".into();
    relay.endpoints = vec![
        pin("127.0.0.1:443".parse().unwrap()),
        pin("127.0.0.2:443".parse().unwrap()),
    ];
    relay.endpoint_bandit = Some(config());
    relay.ca_cert = Some("absent-ca.pem".into());
    relay.inner_tls = Some(aegis_core::secure_channel::ClientSettings {
        server_name: "inner.test".into(),
        server_ca: "absent-inner-ca.pem".into(),
        cert: "absent-device.pem".into(),
        key: "absent-device.key".into(),
    });
    relay.transport_priority = vec![aegis_core::TunnelTransportFamily::GrpcStream];
    relay.udp_transport_priority = Some(vec![aegis_core::TunnelTransportFamily::GrpcDatagram]);
    relay.tls_backend = aegis_core::RelayTlsBackend::Rustls;
    relay.validate_inner_tls_transport().unwrap();
    let mut invalid = Vec::new();
    let mut v = relay.clone();
    v.endpoints[1].server = "dns.test:443".into();
    invalid.push(v);
    let mut v = relay.clone();
    v.endpoints[1] = v.endpoints[0].clone();
    invalid.push(v);
    let mut v = relay.clone();
    v.endpoints[1].server_name = "bad name".into();
    invalid.push(v);
    let mut v = relay.clone();
    v.masque_server = Some("127.0.0.3:443".into());
    invalid.push(v);
    let mut v = relay.clone();
    v.connect_timeout_ms = 60001;
    invalid.push(v);
    let mut v = relay.clone();
    v.endpoint_bandit.as_mut().unwrap().max_profiles = 17;
    invalid.push(v);
    for v in invalid {
        assert!(v.validate_inner_tls_transport().is_err());
    }
}

#[tokio::test]
async fn actual_authenticated_open_without_application_progress_has_no_reward() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, _servers) = pool(directory.path()).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let selection = prepare(&settings.relay, "127.0.0.1", port, "tcp")
        .unwrap()
        .unwrap();
    let ticket = selection
        .attempt(&selection.pool[0].server)
        .unwrap()
        .unwrap();
    let selected = super::super::relay_settings_for_endpoint(&settings.relay, &selection.pool[0]);
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (mut client, _) = local.accept().await.unwrap();
    let counters = super::super::RelaySessionCounters::default();
    let held = counters.clone();
    let mut task = Task(tokio::spawn(async move {
        super::super::secure::run_with_endpoint(
            &mut client,
            &selected,
            "127.0.0.1".into(),
            port,
            None,
            &held,
            Some(&ticket),
            None,
            None,
        )
        .await
        .unwrap();
    }));
    let _destination = tokio::time::timeout(Duration::from_secs(3), target.accept())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(1), async {
        while !counters.was_opened() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(counters.sent(), 0);
    assert_eq!(counters.received(), 0);
    assert_eq!(stats(&selection), vec![(0, 0.0), (0, 0.0)]);
    task.0.abort();
    assert!((&mut task.0).await.unwrap_err().is_cancelled());
    assert_eq!(stats(&selection), vec![(0, 0.0), (0, 0.0)]);
}

#[tokio::test]
async fn observed_response_without_outbound_application_bytes_is_not_success() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, _servers) = pool(directory.path()).await;
    let selection = prepare(&settings.relay, "scripted.test", 443, "tcp")
        .unwrap()
        .unwrap();
    let ticket = selection
        .attempt(&selection.pool[0].server)
        .unwrap()
        .unwrap();
    let counters = super::super::RelaySessionCounters::default();
    counters.mark_opened();
    let (io, mut remote) = tokio::io::duplex(32);
    let mut wrapper =
        super::super::byte_progress::ByteProgress::with_endpoint(io, &counters, Some(&ticket));
    remote.write_all(b"reply").await.unwrap();
    let mut bytes = [0; 5];
    wrapper.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"reply");
    assert_eq!(stats(&selection), vec![(0, 0.0), (0, 0.0)]);
    wrapper.write_all(b"request").await.unwrap();
    assert_eq!(stats(&selection), vec![(1, 1.0), (0, 0.0)]);
    wrapper.write_all(b"more").await.unwrap();
    ticket.terminal_failure();
    assert_eq!(stats(&selection), vec![(1, 1.0), (0, 0.0)]);
}

#[tokio::test]
async fn actual_udp_once_fullwide_and_socks_flows_record_application_progress() {
    let directory = tempfile::tempdir().unwrap();
    let (mut settings, _servers) = pool(directory.path()).await;
    settings.relay.udp_transport_priority =
        Some(vec![aegis_core::TunnelTransportFamily::GrpcDatagram]);
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let mut echo = Task(tokio::spawn(async move {
        let mut bytes = [0; 64];
        for _ in 0..3 {
            let (length, peer) = target.recv_from(&mut bytes).await.unwrap();
            assert!(length > 0);
            target.send_to(&bytes[..length], peer).await.unwrap();
        }
    }));
    let selection = prepare(&settings.relay, "127.0.0.1", port, "udp")
        .unwrap()
        .unwrap();
    let destination = crate::socks5::ConnectTarget {
        host: "127.0.0.1".into(),
        port,
    };
    let reply = tokio::time::timeout(
        Duration::from_secs(5),
        super::super::run_relay_udp_datagram_once(&settings.relay, destination.clone(), b"once"),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(reply, b"once");
    assert_eq!(stats(&selection), vec![(1, 1.0), (0, 0.0)]);
    let (outbound, rx) = tokio::sync::mpsc::channel(2);
    let (tx, mut incoming) = tokio::sync::mpsc::channel(2);
    outbound.send(b"fullwide".to_vec()).await.unwrap();
    let relay = settings.relay.clone();
    let mut fullwide = Task(tokio::spawn(async move {
        super::super::run_relay_udp_flow(&relay, "127.0.0.1", port, rx, tx)
            .await
            .unwrap();
    }));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), incoming.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"fullwide"
    );
    assert_eq!(stats(&selection), vec![(1, 1.0), (1, 1.0)]);
    drop(outbound);
    tokio::time::timeout(Duration::from_secs(5), &mut fullwide.0)
        .await
        .unwrap()
        .unwrap();
    let (outbound, mut rx) = tokio::sync::mpsc::channel(2);
    let (tx, mut incoming) = tokio::sync::mpsc::channel(2);
    outbound.send(b"socks".to_vec()).await.unwrap();
    let relay = settings.relay.clone();
    let mut socks = Task(tokio::spawn(async move {
        super::super::run_relay_udp_associate_flow(relay, destination, &mut rx, &tx)
            .await
            .unwrap();
    }));
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), incoming.recv())
            .await
            .unwrap()
            .unwrap()
            .payload,
        b"socks"
    );
    assert_eq!(stats(&selection), vec![(2, 1.0), (1, 1.0)]);
    drop(outbound);
    tokio::time::timeout(Duration::from_secs(5), &mut socks.0)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), &mut echo.0)
        .await
        .unwrap()
        .unwrap();
}

#[test]
fn inactive_retirement_keeps_sequential_targets_and_profiles_bounded_and_fresh() {
    let mut registry = Registry::default();
    let mut policy = config();
    policy.max_profiles = 2;
    policy.max_contexts_per_profile = 2;
    for i in 0..100 {
        let state = registry.admit([0; 32], [i; 32], &policy).unwrap();
        state.lock().unwrap().estimator.observe("00", 1.0).unwrap();
        drop(state);
        assert!(registry.profiles[&[0; 32]].len() <= 2);
    }
    let returned = registry.admit([0; 32], [0; 32], &policy).unwrap();
    assert_eq!(returned.lock().unwrap().estimator.estimate("00").trials, 0);
    drop(returned);
    for i in 1..100 {
        let state = registry.admit([i; 32], [0; 32], &policy).unwrap();
        assert_eq!(state.lock().unwrap().estimator.estimate("00").trials, 0);
        drop(state);
        assert!(registry.profiles.len() <= 2);
    }
}
#[tokio::test]
async fn live_ticket_prevents_retirement_and_scores_are_fresh_after_release() {
    let directory = tempfile::tempdir().unwrap();
    let (settings, _servers) = pool(directory.path()).await;
    let identity = profile_identity(&settings.relay).unwrap();
    let mut policy = config();
    policy.max_profiles = 1;
    policy.max_contexts_per_profile = 1;
    let mut registry = Registry::default();
    let state = registry.admit(identity, [0; 32], &policy).unwrap();
    let selection = Selection {
        state,
        pool: super::super::effective_relay_endpoints(&settings.relay),
        config: policy.clone(),
        baseline_eligible: OnceLock::new(),
        identity: Arc::new(Identity {
            settings: settings.relay.clone(),
            digest: identity,
        }),
        deadline: tokio::time::Instant::now() + Duration::from_secs(3),
    };
    let ticket = selection
        .attempt(&selection.pool[0].server)
        .unwrap()
        .unwrap();
    ticket.accepted_sent();
    ticket.observed_response();
    drop(selection);
    assert!(registry.admit(identity, [1; 32], &policy).is_err());
    assert_eq!(
        ticket.state.lock().unwrap().estimator.estimate("00").trials,
        1
    );
    drop(ticket);
    drop(registry.admit(identity, [1; 32], &policy).unwrap());
    let fresh = registry.admit(identity, [0; 32], &policy).unwrap();
    assert_eq!(fresh.lock().unwrap().estimator.estimate("00").trials, 0);
}

#[test]
fn actual_rotated_public_certificate_identities_retire_without_old_score_transfer() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let directory = tempfile::tempdir().unwrap();
    let (mut settings, _) = super::super::secure::tests::configs(directory.path(), "127.0.0.1:443");
    settings.relay.auth_token.clear();
    settings.relay.endpoints = vec![
        pin("127.0.0.1:443".parse().unwrap()),
        pin("127.0.0.2:443".parse().unwrap()),
    ];
    let mut policy = config();
    policy.max_profiles = 2;
    policy.max_contexts_per_profile = 2;
    settings.relay.endpoint_bandit = Some(policy.clone());
    let mut registry = Registry::default();
    let original = std::fs::read(settings.relay.ca_cert.as_ref().unwrap()).unwrap();
    let first = profile_identity(&settings.relay).unwrap();
    let state = registry.admit(first, [0; 32], &policy).unwrap();
    state.lock().unwrap().estimator.observe("00", 1.0).unwrap();
    drop(state);
    let mut identities = vec![(first, original)];
    for _ in 0..20 {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let public_pem = cert.cert.pem().into_bytes();
        std::fs::write(settings.relay.ca_cert.as_ref().unwrap(), &public_pem).unwrap();
        let identity = profile_identity(&settings.relay).unwrap();
        assert_ne!(first, identity);
        let state = registry.admit(identity, [0; 32], &policy).unwrap();
        assert_eq!(state.lock().unwrap().estimator.estimate("00").trials, 0);
        state.lock().unwrap().estimator.observe("00", 1.0).unwrap();
        drop(state);
        assert!(registry.profiles.len() <= 2);
        identities.push((identity, public_pem));
    }
    // Inactive profiles retire in lexical digest order, not certificate age.
    // The original digest can legitimately survive all random rotations.
    let (retired, public_pem) = identities
        .into_iter()
        .find(|(identity, _)| !registry.profiles.contains_key(identity))
        .expect("twenty-one observed identities cannot all remain in two slots");
    assert!(!registry.profiles.contains_key(&retired));
    std::fs::write(settings.relay.ca_cert.as_ref().unwrap(), public_pem).unwrap();
    let restored = profile_identity(&settings.relay).unwrap();
    assert_eq!(restored, retired);
    let state = registry.admit(restored, [0; 32], &policy).unwrap();
    assert_eq!(state.lock().unwrap().estimator.estimate("00").trials, 0);
}

fn dependency_policy() -> aegis_core::research_topology::LiveDependencyPolicy {
    use aegis_core::research_topology::{GraphInput, LiveDependencyPolicy};
    let graph = GraphInput {
        nodes: vec![0, 1, 2],
        edges: vec![[0, 1], [1, 2]],
    };
    LiveDependencyPolicy {
        a: graph.clone(),
        b: graph,
        dependency_pairs: vec![[0, 0], [1, 1], [2, 2]],
        endpoint_nodes: vec![0, 2],
        anchor_a: 1,
        anchor_b: 1,
        unavailable_a: vec![],
        unavailable_b: vec![],
    }
}

#[tokio::test]
async fn declared_dependency_changes_actual_two_endpoint_application_selection() {
    let directory = tempfile::tempdir().unwrap();
    let (mut settings, _servers) = pool(directory.path()).await;
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = target.local_addr().unwrap().port();
    let original = prepare(&settings.relay, "127.0.0.1", port, "tcp")
        .unwrap()
        .unwrap();
    let mut policy = dependency_policy();
    policy.unavailable_b = vec![0];
    settings
        .relay
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy = Some(policy);
    let selection = prepare(&settings.relay, "127.0.0.1", port, "tcp")
        .unwrap()
        .unwrap();
    exchange(&settings.relay, &target).await;
    assert_eq!(stats(&selection), vec![(0, 0.0), (1, 1.0)]);
    assert_eq!(stats(&original), vec![(0, 0.0), (0, 0.0)]);
    // Policy and ordered endpoint-to-node mapping are part of the fresh identity.
    let mut reordered = settings.relay.clone();
    reordered.endpoints.swap(0, 1);
    reordered.server = reordered.endpoints[0].server.clone();
    reordered
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy
        .as_mut()
        .unwrap()
        .endpoint_nodes
        .swap(0, 1);
    let fresh = prepare(&reordered, "127.0.0.1", port, "tcp")
        .unwrap()
        .unwrap();
    assert_eq!(stats(&fresh), vec![(0, 0.0), (0, 0.0)]);
    assert_eq!(
        fresh.rank(fresh.pool.clone()).unwrap()[0].server,
        settings.relay.endpoints[1].server
    );
}

async fn refused_without_dial(settings: &RelaySettings, target: &TcpListener) {
    let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let _app = TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    assert!(tokio::time::timeout(
        Duration::from_secs(5),
        super::super::run_relay_tunnel(
            client,
            settings,
            "127.0.0.1".into(),
            target.local_addr().unwrap().port(),
            Some(b"must not replay"),
            None,
            None,
        )
    )
    .await
    .unwrap()
    .is_err());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn declared_anchor_loss_refuses_actual_caller_before_private_key_or_either_dial() {
    let directory = tempfile::tempdir().unwrap();
    let (mut settings, _servers) = pool(directory.path()).await;
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    settings.relay.endpoints = vec![
        pin(first.local_addr().unwrap()),
        pin(second.local_addr().unwrap()),
    ];
    settings.relay.server = settings.relay.endpoints[0].server.clone();
    settings.relay.inner_tls.as_mut().unwrap().key = directory.path().join("absent-private-key");
    let mut policy = dependency_policy();
    policy.unavailable_b = vec![1];
    settings
        .relay
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy = Some(policy);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    refused_without_dial(&settings.relay, &target).await;
    for listener in [&first, &second] {
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }
    let selection = prepare(
        &settings.relay,
        "127.0.0.1",
        target.local_addr().unwrap().port(),
        "tcp",
    )
    .unwrap()
    .unwrap();
    assert_eq!(stats(&selection), vec![(0, 0.0), (0, 0.0)]);
}

#[tokio::test]
async fn pre_auth_failure_recomputes_cascade_before_previously_ranked_backup_dial() {
    let directory = tempfile::tempdir().unwrap();
    let (mut settings, mut servers) = pool(directory.path()).await;
    let backup = TcpListener::bind("127.0.0.1:0").await.unwrap();
    settings.relay.endpoints[1] = pin(backup.local_addr().unwrap());
    let mut policy = dependency_policy();
    policy.endpoint_nodes = vec![1, 2];
    settings
        .relay
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy = Some(policy);
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let selection = prepare(
        &settings.relay,
        "127.0.0.1",
        target.local_addr().unwrap().port(),
        "tcp",
    )
    .unwrap()
    .unwrap();
    assert_eq!(selection.rank(selection.pool.clone()).unwrap().len(), 2);
    servers[0].0.abort();
    (&mut servers[0].0).await.unwrap_err();
    refused_without_dial(&settings.relay, &target).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), backup.accept())
            .await
            .is_err()
    );
    assert_eq!(stats(&selection), vec![(1, 0.0), (0, 0.0)]);
    assert!(selection
        .attempt(&selection.pool[1].server)
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn dependency_eligibility_cannot_expand_and_original_clock_never_resets() {
    let directory = tempfile::tempdir().unwrap();
    let (mut settings, _servers) = pool(directory.path()).await;
    settings
        .relay
        .endpoint_bandit
        .as_mut()
        .unwrap()
        .dependency_policy = Some(dependency_policy());
    let mut selection = prepare(&settings.relay, "bounded", 443, "tcp")
        .unwrap()
        .unwrap();
    assert!(selection.attempt(&selection.pool[0].server).is_err());
    assert_eq!(
        selection
            .rank(vec![selection.pool[1].clone()])
            .unwrap()
            .len(),
        1
    );
    assert!(selection
        .attempt(&selection.pool[0].server)
        .unwrap()
        .is_none());
    assert!(selection.rank(selection.pool.clone()).is_err());
    selection.deadline = tokio::time::Instant::now();
    assert!(selection.attempt(&selection.pool[1].server).is_err());
    assert!(selection.rank(vec![selection.pool[1].clone()]).is_err());
}

#[test]
fn dependency_bounds_null_unknown_and_mapping_refuse_purely_before_identity_io() {
    let mut value = serde_json::to_value(config()).unwrap();
    value["dependency_policy"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<RelayEndpointBanditSettings>(value.clone()).is_err());
    value["dependency_policy"] = serde_json::to_value(dependency_policy()).unwrap();
    value["dependency_policy"]["discover"] = true.into();
    assert!(serde_json::from_value::<RelayEndpointBanditSettings>(value).is_err());
    let mut relay = RelaySettings {
        auth_token: String::new(),
        server: "127.0.0.1:443".into(),
        server_name: "localhost".into(),
        endpoints: vec![
            pin("127.0.0.1:443".parse().unwrap()),
            pin("127.0.0.2:443".parse().unwrap()),
        ],
        ca_cert: Some("absent-public-ca.pem".into()),
        inner_tls: Some(aegis_core::secure_channel::ClientSettings {
            server_name: "inner.test".into(),
            server_ca: "absent-inner-ca.pem".into(),
            cert: "absent-device.pem".into(),
            key: "absent-private.key".into(),
        }),
        tls_backend: aegis_core::RelayTlsBackend::Rustls,
        transport_priority: vec![aegis_core::TunnelTransportFamily::GrpcStream],
        udp_transport_priority: Some(vec![aegis_core::TunnelTransportFamily::GrpcDatagram]),
        endpoint_bandit: Some(config()),
        ..Default::default()
    };
    relay.validate_inner_tls_transport().unwrap();
    let expired = tokio::time::Instant::now() - Duration::from_millis(relay.connect_timeout_ms + 1);
    let expired_error = prepare_at(&relay, "target", 443, "tcp", Some(expired))
        .err()
        .unwrap()
        .to_string();
    assert!(expired_error.contains("before public identity"));
    let mut policy = dependency_policy();
    policy.endpoint_nodes = vec![0, 0];
    relay.endpoint_bandit.as_mut().unwrap().dependency_policy = Some(policy);
    let error = relay.validate_inner_tls_transport().unwrap_err();
    assert!(error.contains("endpoint") || error.contains("bound"));
    assert!(!error.contains("certificate"));
    let error = prepare(&relay, "target", 443, "tcp")
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("duplicate live endpoint node"));
}
