//! Actual synthetic authorized TLS/H2 consumers; never native field acceptance.
use super::*;
fn profile() -> aegis_core::carrier_runtime::PrivacySettings {
    let mut p = shaping_profile();
    p.io_timeout_ms = 2000;
    p.max_queue_delay_ms = 3_000_000;
    p.liu_channel=Some(serde_json::from_value(serde_json::json!({"class_weights":[1,3],"client_to_server_counts":[[3,1],[1,3]],"server_to_client_counts":[[3,1],[1,3]],"target_classes":[],"unmatched_traffic_class":0,"policy_ack_class":1,"distortion_microunits":125000,"optimizer_iterations":2000,"optimizer_gap_millibits":1,"optimizer_timeout_ms":3000,"buffer_bytes":1024,"wire_batch_bytes":1024,"max_wire_bytes":100000,"io_timeout_ms":2000,"session_timeout_ms":10000,"max_queue_delay_ms":3000000})).unwrap());
    p.validate().unwrap();
    p
}

#[tokio::test]
async fn liu_opaque_public_entry_refuses_before_tls_and_authentication_callback() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let f = fixture(true);
    let limiter = RateLimiter::new(1, 300, true);
    let p = profile();
    p.validate().unwrap();
    let ctx = context(&f, &limiter, "192.0.2.73:443");
    let (carrier, mut peer) = tokio::io::duplex(1024);
    let authenticated = AtomicBool::new(false);
    // Peer sends no ClientHello. A handshake here would wait for its timer;
    // unsupported settings must refuse before even starting authorization.
    let result = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        crate::session::serve_device_carrier(
            carrier,
            f.server,
            &ctx.target_policy,
            &limiter,
            Some("192.0.2.73".parse().unwrap()),
            || {
                authenticated.store(true, Ordering::SeqCst);
                Ok(())
            },
            Some(&p),
        ),
    )
    .await
    .unwrap()
    .unwrap_err();
    let error = result.downcast_ref::<std::io::Error>().unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    assert!(!authenticated.load(Ordering::SeqCst));
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
    assert!(!limiter.is_banned("192.0.2.73".parse().unwrap()).await);
}

async fn admitted(
    client: Client,
    carrier: GrpcIo<H2Stream>,
    p: &aegis_core::carrier_runtime::PrivacySettings,
    c: aegis_core::traffic_privacy::liu_channel::BoundContext,
) -> aegis_core::carrier_runtime::OwnedCarrier {
    let origin = tokio::time::Instant::now();
    let deadline = origin + std::time::Duration::from_secs(3);
    let prepared = secure_channel::relay_shaping::prepare_liu_admission(p, c, origin, deadline)
        .await
        .unwrap();
    let tls = client.connect(carrier).await.unwrap();
    assert_eq!(
        tls.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    secure_channel::relay_shaping::client_admitted(tls, Some(p), deadline, Some(prepared))
        .await
        .unwrap()
}
#[tokio::test]
async fn liu_actual_authorized_tls_h2_nonconstant_target_transfer_and_halfclose() {
    let f = fixture(true);
    let limiter = RateLimiter::new(1, 300, true);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut target = Driver(tokio::spawn(async move {
        let (mut remote, _) = listener.accept().await.unwrap();
        let mut data = Vec::new();
        remote.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, b"nonconstant-data");
        remote.write_all(b"full-response").await.unwrap();
        remote.shutdown().await.unwrap();
    }));
    let p = profile();
    let mut ctx = context(&f, &limiter, "192.0.2.70:443");
    ctx.transport.authenticated_shaping = Some(p.clone());
    ctx.target_policy.profile = crate::config::TargetPolicyProfile::FullVpnEgress;
    let client = f.client.clone();
    exchange(ctx, None, |carrier| async move {
        let c = p
            .liu_channel
            .as_ref()
            .unwrap()
            .traffic_context("127.0.0.1", port, secure_channel::Transport::Tcp)
            .unwrap();
        let mut s = admitted(client, carrier, &p, c).await;
        secure_channel::write_open(
            &mut s,
            &secure_channel::OpenRequest {
                version: 1,
                host: "127.0.0.1".into(),
                port,
                transport: secure_channel::Transport::Tcp,
            },
        )
        .await
        .unwrap();
        assert_eq!(s.read_u8().await.unwrap(), 0);
        s.write_all(b"nonconstant-data").await.unwrap();
        s.shutdown().await.unwrap();
        let mut response = Vec::new();
        s.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"full-response");
    })
    .await
    .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), &mut target.0)
        .await
        .unwrap()
        .unwrap();
    assert!(!limiter.is_banned("192.0.2.70".parse().unwrap()).await);
}
#[tokio::test]
async fn liu_bound_target_and_policy_purpose_refuse_before_actual_target_accept() {
    for policy_mismatch in [false, true] {
        let f = fixture(true);
        let limiter = RateLimiter::new(1, 300, true);
        let target = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = target.local_addr().unwrap().port();
        let p = profile();
        let mut ctx = context(&f, &limiter, "192.0.2.71:443");
        ctx.transport.authenticated_shaping = Some(p.clone());
        ctx.target_policy.profile = crate::config::TargetPolicyProfile::FullVpnEgress;
        let client = f.client.clone();
        let result = exchange(ctx, None, |carrier| async move {
            let c = p
                .liu_channel
                .as_ref()
                .unwrap()
                .traffic_context("admitted.test", 443, secure_channel::Transport::Tcp)
                .unwrap();
            let mut s = admitted(client, carrier, &p, c).await;
            if policy_mismatch {
                secure_channel::policy_ack::write_request(
                    &mut s,
                    &secure_channel::policy_ack::PolicyAckRequest::new(),
                )
                .await
                .unwrap();
                assert!(secure_channel::policy_ack::read_ack(&mut s).await.is_err());
            } else {
                secure_channel::write_open(
                    &mut s,
                    &secure_channel::OpenRequest {
                        version: 1,
                        host: "127.0.0.1".into(),
                        port,
                        transport: secure_channel::Transport::Tcp,
                    },
                )
                .await
                .unwrap();
                assert!(s.read_u8().await.is_err());
            }
        })
        .await;
        assert!(result.is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), target.accept())
                .await
                .is_err()
        );
        assert!(!limiter.is_banned("192.0.2.71".parse().unwrap()).await);
    }
}
#[cfg(unix)] // publish_snapshot intentionally requires Unix durable publication.
#[tokio::test]
async fn liu_explicit_policy_ack_class_crosses_actual_live_registry_lease_without_target() {
    use secure_channel::{policy_ack, registry};
    let mut f = fixture(true);
    let now = registry::unix_now().unwrap();
    let fingerprint = f.server_settings.allowed_client_sha256[0].clone();
    let path = f._dir.path().join("liu-registry.json");
    let mut snapshot = registry::DeviceRegistry::new(now, 900).unwrap();
    snapshot.devices.push(registry::DeviceRecord {
        device_id: "liu-synthetic-device".into(),
        certificate_sha256: fingerprint.clone(),
        not_after_unix_secs: now + 600,
        revoked: false,
    });
    registry::publish_snapshot(&path, &snapshot).unwrap();
    f.server_settings.allowed_client_sha256.clear();
    f.server_settings.device_registry = Some(path);
    f.server = Server::load(&f.server_settings).unwrap();
    let _watcher = f.server.start_registry_watcher().unwrap();
    let client = f.client.clone();
    let digest = hex::encode(registry::registry_digest(&snapshot).unwrap());
    let limiter = RateLimiter::new(1, 300, true);
    let p = profile();
    let mut ctx = context(&f, &limiter, "192.0.2.72:443");
    ctx.transport.authenticated_shaping = Some(p.clone());
    let observation = std::sync::Arc::new(std::sync::Mutex::new(None));
    let observed = observation.clone();
    let result = exchange(ctx, None, |carrier| async move {
        let context = p.liu_channel.as_ref().unwrap().policy_context().unwrap();
        let mut s = admitted(client, carrier, &p, context).await;
        let request = policy_ack::PolicyAckRequest::new();
        policy_ack::write_request(&mut s, &request).await.unwrap();
        s.shutdown().await.unwrap();
        let ack = match policy_ack::read_ack(&mut s).await {
            Ok(ack) => ack,
            Err(e) => {
                *observed.lock().unwrap() = Some((e.kind(), e.to_string()));
                return;
            }
        };
        ack.verify(
            &request.nonce,
            &fingerprint,
            Some((snapshot.generation, &digest)),
            now,
            std::time::Duration::ZERO,
        )
        .unwrap();
        assert_eq!(s.read(&mut [0]).await.unwrap(), 0);
    })
    .await;
    assert!(result.is_ok(), "server result: {result:?}");
    assert!(
        observation.lock().unwrap().is_none(),
        "client failure: {:?}",
        observation.lock().unwrap()
    );
    assert!(!limiter.is_banned("192.0.2.72".parse().unwrap()).await);
}
