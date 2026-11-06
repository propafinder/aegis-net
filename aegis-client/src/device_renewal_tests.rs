#[tokio::test]
async fn actual_supervisor_retains_authenticated_ack_deadline_across_confirmation() {
    let f = Fixture::new().await;
    let authority = f.server().await;
    redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: Some(f.invitation.clone()),
    })
    .await
    .unwrap();
    authority.stop().await;
    let settings = f.settings();
    let relay = f.relay(&f.config.issuer.registry).await;
    let supervisor = Supervisor::start(Some(&f.bundle), &settings).await.unwrap();
    let initial = supervisor
        .retained_ack_deadline_for_test()
        .unwrap()
        .unwrap();
    assert!(initial > tokio::time::Instant::now());
    supervisor.confirm_before_ready().await.unwrap();
    let refreshed = supervisor
        .retained_ack_deadline_for_test()
        .unwrap()
        .unwrap();
    assert!(refreshed > tokio::time::Instant::now());
    // Reconfirmation performs the real ACK exchange and retains that result;
    // it cannot return unit while silently throwing away the deadline.
    assert!(refreshed <= tokio::time::Instant::now() + Duration::from_secs(3));
    supervisor.ensure_confirmation_current().unwrap();
    // Exercise the real readiness consumer after an idle synchronous handoff
    // outlives the retained authenticated grant. No extra ACK is requested.
    tokio::time::sleep_until(refreshed).await;
    let error = crate::service_ready::after_confirmation(async { Ok(()) }, || {
        supervisor.ensure_confirmation_current()
    })
    .await
    .unwrap_err();
    assert!(error.to_string().contains("acknowledgement expired"));
    drop(supervisor);
    relay.stop().await;
}

use super::*;
use crate::device_renewal::Supervisor;

#[tokio::test]
async fn owned_monitor_rejects_removed_issuance_floor_without_certificate_change() {
    let f = Fixture::new().await;
    let authority = f.server().await;
    redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: Some(f.invitation.clone()),
    })
    .await
    .unwrap();
    authority.stop().await;
    let settings = f.settings();
    let relay = f.relay(&f.config.issuer.registry).await;
    let mut supervisor = Supervisor::start(Some(&f.bundle), &settings).await.unwrap();
    supervisor.confirm_before_ready().await.unwrap();
    let certificate = fs::read(f.identity.join("device.pem")).unwrap();
    let pinned = store::online_expectation(
        &f.identity,
        f.profile().digest(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    assert!(pinned.issued_generation.is_some());
    fs::remove_file(f.identity.join("online-completed.json")).unwrap();
    let current = store::online_expectation(
        &f.identity,
        f.profile().digest(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    assert_eq!(current.certificate_sha256, pinned.certificate_sha256);
    assert_eq!(current.not_after_unix_secs, pinned.not_after_unix_secs);
    assert!(current.issued_generation.is_none());
    // The actual five-second task observes the on-disk mutation. The issuer
    // is stopped, so this cannot succeed through network renewal or a new ACK.
    let reason = tokio::time::timeout(Duration::from_secs(7), supervisor.failure())
        .await
        .unwrap();
    assert_eq!(
        reason,
        "device issuance changed; authenticated restart required"
    );
    assert!(supervisor.confirm_before_ready().await.is_err());
    assert_eq!(
        fs::read(f.identity.join("device.pem")).unwrap(),
        certificate
    );
    assert!(!f.identity.join("online-request.json").exists());
    drop(supervisor);
    relay.stop().await;
}

#[tokio::test]
async fn prepared_startup_rejects_removed_issuance_floor_before_live_ack() {
    let f = Fixture::new().await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let authority = f.server().await;
    let prepared = crate::device_renewal::PreparedIdentity::prepare(&f.bundle, &settings, true)
        .await
        .unwrap();
    let certificate = fs::read(f.identity.join("device.pem")).unwrap();
    let pinned = store::online_expectation(
        &f.identity,
        f.profile().digest(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    assert!(pinned.issued_generation.is_some());
    fs::remove_file(f.identity.join("online-completed.json")).unwrap();
    let changed = store::online_expectation(
        &f.identity,
        f.profile().digest(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    assert_eq!(changed.certificate_sha256, pinned.certificate_sha256);
    assert!(changed.issued_generation.is_none());
    let error = match prepared.confirm().await {
        Ok(_) => panic!("changed issuance must not inherit prepared readiness"),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), "device identity changed during startup");
    assert_eq!(
        fs::read(f.identity.join("device.pem")).unwrap(),
        certificate
    );
    authority.stop().await;
}

#[tokio::test]
async fn https_bridge_native_renewal_tcp_udp_policy_ack_and_revocation() {
    assert_https_bridge_renewal(TestFraming::Disabled).await;
}

#[tokio::test]
async fn authenticated_shaping_https_bridge_renewal_tcp_udp_policy_ack_and_revocation() {
    assert_https_bridge_renewal(TestFraming::ConstantCadence).await;
}

#[tokio::test]
async fn admitted_exponential_https_bridge_renewal_tcp_udp_policy_ack_and_revocation() {
    assert_https_bridge_renewal(TestFraming::ExponentialProposals).await;
}

#[derive(Clone, Copy)]
enum TestFraming {
    Disabled,
    ConstantCadence,
    ExponentialProposals,
}

async fn assert_https_bridge_renewal(framing: TestFraming) {
    // Construct the policy before installation so the managed renderer,
    // authority digest and runtime pin all refer to the same public bytes.
    let mut policy = aegis_core::Settings::default();
    policy.relay.authenticated_shaping = (!matches!(framing, TestFraming::Disabled)).then_some(
        aegis_core::carrier_runtime::PrivacySettings {
            payload_bytes: 1024,
            cadence_ms: 1,
            buffer_bytes: 4096,
            max_wire_bytes: 16 * 1024 * 1024,
            io_timeout_ms: 100,
            session_timeout_ms: 30_000,
            max_queue_delay_ms: 1000,
            poisson_pacing: None,
            net_shaper: None,
            adaptive_channel: None,
            arrival_envelope: None,
            cover_stream: None,
            bit_traps: None,
            liu_channel: None,
        },
    );
    if let Some(profile) = &mut policy.relay.authenticated_shaping {
        let owner = if matches!(framing, TestFraming::ExponentialProposals) {
            profile.cadence_ms = 1000;
            profile.max_queue_delay_ms = 20_000;
            profile.poisson_pacing = Some(aegis_core::traffic_privacy::poisson::PoissonPacing {
                mean_interval_us: 1000,
                max_gap_us: 1_000_000,
            });
            aegis_core::traffic_privacy::plan::PacketModifier::PoissonSchedule
        } else {
            aegis_core::traffic_privacy::plan::PacketModifier::ConstantCadence
        };
        policy.privacy_plan = Some(aegis_core::traffic_privacy::plan::PrivacyPlan {
            packet_modifiers: vec![owner],
            framing_budget: Some(aegis_core::traffic_privacy::plan::FramingBudget {
                max_payload_bytes: profile.payload_bytes,
                max_buffer_bytes: profile.buffer_bytes,
                max_wire_bytes_per_direction: profile.max_wire_bytes,
                max_session_ms: profile.session_timeout_ms,
                max_queue_delay_ms: profile.max_queue_delay_ms,
            }),
            ..Default::default()
        });
    }
    let f = Fixture::new_with_research_policy(
        true,
        false,
        policy.relay.authenticated_shaping.clone(),
        policy.privacy_plan.clone(),
    )
    .await;
    f.install_due_predecessor().await;
    // settings() exercises the real bundle renderer and file loader.
    let settings = f.settings();
    assert_eq!(
        settings.relay.authenticated_shaping,
        policy.relay.authenticated_shaping
    );
    assert_eq!(
        serde_json::to_value(&settings.privacy_plan).unwrap(),
        serde_json::to_value(&policy.privacy_plan).unwrap()
    );
    let original_key = f.key();
    let authority = f.server().await;
    let relay = f
        .relay_with_shaping(
            &f.config.issuer.registry,
            settings.relay.authenticated_shaping.clone(),
        )
        .await;
    let supervisor = Supervisor::start(Some(&f.bundle), &settings).await.unwrap();
    supervisor.confirm_before_ready().await.unwrap();
    assert_eq!(f.key(), original_key);
    assert!(settings.relay.https_bridge.is_some());

    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let target_task = tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut stream, _) = target.accept().await.unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"private bridge TCP payload");
        stream.write_all(b"bridge TCP response").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut app = tokio::net::TcpStream::connect(local.local_addr().unwrap())
        .await
        .unwrap();
    let (client, _) = local.accept().await.unwrap();
    let traffic = settings.relay.clone();
    let tunnel = tokio::spawn(async move {
        crate::relay::run_relay_tunnel(
            client,
            &traffic,
            "127.0.0.1".into(),
            target_port,
            None,
            None,
            None,
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        app.write_all(b"private bridge TCP payload").await.unwrap();
        app.shutdown().await.unwrap();
        let mut reply = Vec::new();
        app.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, b"bridge TCP response");
        tunnel.await.unwrap().unwrap();
        target_task.await.unwrap();
    })
    .await
    .unwrap();

    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_port = target.local_addr().unwrap().port();
    let echo = tokio::spawn(async move {
        let mut buffer = [0; 256];
        for _ in 0..2 {
            let (length, source) = target.recv_from(&mut buffer).await.unwrap();
            target.send_to(&buffer[..length], source).await.unwrap();
        }
    });
    for payload in [b"".as_slice(), b"private bridge UDP payload".as_slice()] {
        let reply = crate::relay::run_relay_udp_datagram_once(
            &settings.relay,
            crate::socks5::ConnectTarget {
                host: "127.0.0.1".into(),
                port: target_port,
            },
            payload,
        )
        .await
        .unwrap();
        assert_eq!(reply, payload);
    }
    echo.await.unwrap();
    let expected = store::online_expectation(
        &f.identity,
        f.profile().digest(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    assert!(
        crate::relay::policy_ack(&settings.relay, &expected)
            .await
            .unwrap()
            > tokio::time::Instant::now()
    );
    aegis_server::devices::revoke(&f.config.issuer.registry, "device-a").unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if crate::relay::policy_ack(&settings.relay, &expected)
                .await
                .is_err()
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    drop(supervisor);
    relay.stop().await;
    authority.stop().await;
}

#[tokio::test]
async fn https_bridge_removal_stops_startup_before_pending_renewal_or_network() {
    let f = Fixture::new_with_bridge(true).await;
    f.install_due_predecessor().await;
    let mut settings = f.settings();
    settings.relay.https_bridge = None;
    assert!(Supervisor::start(Some(&f.bundle), &settings).await.is_err());
    assert!(!f.identity.join("online-request.json").exists());
}

#[tokio::test]
async fn https_bridge_wrong_gate_legacy_route_and_policy_downgrades_never_reach_target() {
    let f = Fixture::new_with_bridge(true).await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let relay = f.relay(&f.config.issuer.registry).await;
    let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let wrong_gate = f.identity.join("wrong-bridge-credential");
    enrollment::write_private_new(&wrong_gate, &[b'b'; 64]).unwrap();
    let mut cases = Vec::new();
    let mut wrong = settings.relay.clone();
    wrong.https_bridge.as_mut().unwrap().credential_file = wrong_gate;
    cases.push(wrong);
    let mut legacy_route = settings.relay.clone();
    legacy_route.https_bridge = None;
    cases.push(legacy_route);
    let mut wrong_authority = settings.relay.clone();
    wrong_authority.https_bridge.as_mut().unwrap().authority = "foreign.test".into();
    cases.push(wrong_authority);
    let mut no_inner = settings.relay.clone();
    no_inner.inner_tls = None;
    cases.push(no_inner);
    let mut legacy_transport = settings.relay.clone();
    legacy_transport.transport_priority = vec![aegis_core::TunnelTransportFamily::LegacyTls];
    cases.push(legacy_transport);
    for relay_settings in cases {
        let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let _app = tokio::net::TcpStream::connect(local.local_addr().unwrap())
            .await
            .unwrap();
        let (client, _) = local.accept().await.unwrap();
        assert!(crate::relay::run_relay_tunnel(
            client,
            &relay_settings,
            "127.0.0.1".into(),
            target.local_addr().unwrap().port(),
            Some(b"must not reach target"),
            None,
            None
        )
        .await
        .is_err());
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    relay.stop().await;
}

#[tokio::test]
async fn installed_startup_renews_same_key_then_waits_for_live_relay_ack() {
    let f = Fixture::new().await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let key = f.key();
    let previous = fs::read(f.identity.join("device.pem")).unwrap();
    let authority = f.server().await;
    let relay = f.relay(&f.config.issuer.registry).await;
    let supervisor = Supervisor::start(Some(&f.bundle), &settings).await.unwrap();
    supervisor.confirm_before_ready().await.unwrap();
    assert_eq!(f.key(), key);
    assert_ne!(fs::read(f.identity.join("device.pem")).unwrap(), previous);
    let expected = store::online_expectation(
        &f.identity,
        f.profile().digest(),
        registry::unix_now().unwrap(),
    )
    .unwrap();
    assert!(expected.issued_generation.is_some());
    drop(supervisor);
    relay.stop().await;
    authority.stop().await;
}

#[tokio::test]
async fn committed_issuance_withheld_from_relay_cannot_pass_startup_or_ready() {
    let f = Fixture::new().await;
    f.install_due_predecessor().await;
    let settings = f.settings();
    let separate = f._dir.path().join("unadopted-registry.json");
    let old = fs::read(&f.config.issuer.registry).unwrap();
    // A relay snapshot includes the registry's protected reader lock/floor,
    // so publish the independent copy through the real registry writer.
    let transaction = RegistryTransaction::begin(&separate).unwrap();
    let data: registry::DeviceRegistry = serde_json::from_slice(&old).unwrap();
    transaction.save(&separate, &data, true).unwrap();
    drop(transaction);
    let authority = f.server().await;
    let relay = f.relay(&separate).await;
    let error = match Supervisor::start(Some(&f.bundle), &settings).await {
        Ok(_) => panic!("unadopted issuance must not activate ingress"),
        Err(error) => error,
    };
    assert_eq!(
        error.to_string(),
        "live relay policy has not confirmed this device; ingress remains blocked"
    );
    assert!(
        error.chain().nth(1).is_some(),
        "the real inner-TLS refusal must survive the startup context"
    );
    assert!(
        error.downcast_ref::<std::io::Error>().is_some(),
        "the transport error must retain its type for private classification"
    );
    let status = store::online_status(&f.identity, registry::unix_now().unwrap()).unwrap();
    assert_eq!(status.state, "ready", "local certificate completed");
    assert!(!status.pending, "network delivery completed locally");
    assert_eq!(fs::read(&separate).unwrap(), old);
    assert_ne!(fs::read(&f.config.issuer.registry).unwrap(), old);
    relay.stop().await;
    authority.stop().await;
}

#[tokio::test]
async fn installed_config_mismatch_refuses_before_renewal_pending_or_network() {
    let f = Fixture::new().await;
    f.install_due_predecessor().await;
    let mut settings = f.settings();
    settings.relay.server_name = "replacement.test".into();
    let certificate = fs::read(f.identity.join("device.pem")).unwrap();
    assert!(Supervisor::start(Some(&f.bundle), &settings).await.is_err());
    assert!(!f.identity.join("online-request.json").exists());
    assert_eq!(
        fs::read(f.identity.join("device.pem")).unwrap(),
        certificate
    );
}

#[tokio::test]
async fn disabling_online_flag_retains_legacy_no_network_startup() {
    let mut supervisor = Supervisor::start(None, &aegis_core::Settings::default())
        .await
        .unwrap();
    supervisor.confirm_before_ready().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(20), supervisor.failure())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn owned_monitor_requests_restart_for_due_or_pending_without_sending_renewal() {
    let f = Fixture::new().await;
    let authority = f.server().await;
    redeem(&RedeemArgs {
        identity_dir: f.identity.clone(),
        bundle_dir: f.bundle.clone(),
        invitation_file: Some(f.invitation.clone()),
    })
    .await
    .unwrap();
    authority.stop().await;
    let settings = f.settings();
    let relay = f.relay(&f.config.issuer.registry).await;
    let mut supervisor = Supervisor::start(Some(&f.bundle), &settings).await.unwrap();
    let now = registry::unix_now().unwrap();
    let expected = store::online_expectation(&f.identity, f.profile().digest(), now).unwrap();
    let status = store::online_status(&f.identity, now).unwrap();
    let start = status.not_before_unix_secs.unwrap();
    let end = status.not_after_unix_secs.unwrap();
    let due = start + (end - start) * 2 / 3;
    assert!(crate::device_renewal::monitor_at(
        &f.identity,
        f.profile().digest(),
        &expected.certificate_sha256,
        now
    )
    .is_none());
    assert!(crate::device_renewal::monitor_at(
        &f.identity,
        f.profile().digest(),
        &expected.certificate_sha256,
        due
    )
    .is_some());
    assert!(crate::device_renewal::monitor_at(
        &f.identity,
        f.profile().digest(),
        &expected.certificate_sha256,
        end
    )
    .is_some());
    // A durable pending operation is observed by the actual task without any
    // network issuance: the authority is already stopped, and no cert changes.
    let certificate = fs::read(f.identity.join("device.pem")).unwrap();
    store::begin_online_request(
        &f.identity,
        Operation::Renew,
        f.profile().digest(),
        None,
        due,
    )
    .unwrap();
    let reason = tokio::time::timeout(Duration::from_secs(7), supervisor.failure())
        .await
        .unwrap();
    assert_eq!(reason, "device renewal requires restart before issuance");
    assert_eq!(
        fs::read(f.identity.join("device.pem")).unwrap(),
        certificate
    );
    assert!(f.identity.join("online-request.json").exists());
    drop(supervisor);
    relay.stop().await;
}
