//! Resource regressions use real H2/WS framing and synthetic credentials only.
use super::*;
use std::future::Future;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::Semaphore;

struct Task<T>(tokio::task::JoinHandle<T>);
impl<T> Drop for Task<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn legacy_auth() -> TunnelAuthKeyring {
    TunnelAuthKeyring {
        keys: Vec::new().into(),
        operational_log: Default::default(),
        inner_tls: None,
        https_bridge: None,
        fronted_origin: None,
        relay_training: None,
    }
}

async fn settle() {
    for _ in 0..20 {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_h2_silent_connection_releases_global_permit() {
    for completes_h2 in [false, true] {
        let (client, server_io) = tokio::io::duplex(64 * 1024);
        let permits = Arc::new(Semaphore::new(1));
        let permit = permits.clone().try_acquire_owned().unwrap();
        let mut owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
        let registry = owner.registry();
        let server = Task(tokio::spawn(async move {
            let _permit = permit;
            handle_grpc_session_with_owner(
                server_io,
                &legacy_auth(),
                &TransportConfig::default(),
                &TargetPolicyConfig::default(),
                &RateLimiter::new(8, 60, false),
                "192.0.2.10:443".parse().unwrap(),
                None,
                &registry,
                None,
            )
            .await
        }));
        let (_sender, _driver, _silent_io) = if completes_h2 {
            let (sender, driver) = h2::client::handshake(client).await.unwrap();
            (Some(sender), Some(Task(tokio::spawn(driver))), None)
        } else {
            (None, None, Some(client))
        };
        settle().await;
        tokio::time::advance(Duration::from_secs(31)).await;
        settle().await;
        assert!(
            server.0.is_finished(),
            "silent H2 peer must expire, completes_h2={completes_h2}"
        );
        assert_eq!(
            permits.available_permits(),
            1,
            "connection budget reclaimed"
        );
        owner.shutdown().await;
    }
}

#[tokio::test]
async fn relay_preauth_shared_token_h2_advertises_a_stream_cap() {
    let (client, server_io) = tokio::io::duplex(64 * 1024);
    let mut owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
    let registry = owner.registry();
    let _server = Task(tokio::spawn(async move {
        handle_grpc_session_with_owner(
            server_io,
            &legacy_auth(),
            &TransportConfig::default(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            &registry,
            None,
        )
        .await
    }));
    let (_sender, mut connection) = h2::client::handshake(client).await.unwrap();
    let maximum = Arc::new(AtomicUsize::new(usize::MAX));
    let observed = maximum.clone();
    let _driver = Task(tokio::spawn(std::future::poll_fn(move |cx| {
        let result = std::pin::Pin::new(&mut connection).poll(cx);
        observed.store(connection.max_concurrent_send_streams(), Ordering::SeqCst);
        result
    })));
    settle().await;
    assert_eq!(
        maximum.load(Ordering::SeqCst),
        32,
        "shared-token H2 SETTINGS bound streams"
    );
    owner.shutdown().await;
}

#[tokio::test]
async fn relay_preauth_grpc_rejects_oversized_prefix_without_waiting_for_body() {
    let (client, server_io) = tokio::io::duplex(64 * 1024);
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let _server = Task(tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let (request, respond) = connection.accept().await.unwrap().unwrap();
        let handling = handle_single_grpc_request(
            request,
            respond,
            GrpcRequestContext {
                witness: None,
                bridge_activity: None,
                transport: TransportConfig::default(),
                target_policy: TargetPolicyConfig::default(),
                auth_keyring: legacy_auth(),
                rate_limiter: RateLimiter::new(8, 60, false),
                peer: "192.0.2.10:443".parse().unwrap(),
                bundle_ctx: None,
                admission: None,
            },
        );
        tokio::pin!(handling);
        tokio::select! {
            result = &mut handling => { let _ = result_tx.send(result); }
            next = connection.accept() => panic!("unexpected H2 close: {next:?}"),
        }
    }));
    let (mut sender, driver) = h2::client::handshake(client).await.unwrap();
    let _driver = Task(tokio::spawn(driver));
    let path = TransportConfig::default().grpc_path;
    let request = http::Request::builder()
        .method("POST")
        .uri(path)
        .body(())
        .unwrap();
    let (_response, mut send) = sender.send_request(request, false).unwrap();
    let mut prefix = vec![0];
    prefix.extend_from_slice(&((MAX_TUNNEL_REQUEST_BYTES + 1) as u32).to_be_bytes());
    send.send_data(Bytes::from(prefix), false).unwrap();
    let result = tokio::time::timeout(Duration::from_millis(100), result_rx)
        .await
        .expect("oversized pre-auth length refused before payload allocation")
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("length"));
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_websocket_silent_open_releases_global_permit() {
    let (_client, server_io) = tokio::io::duplex(8192);
    let ws = tokio_tungstenite::WebSocketStream::from_raw_socket(
        server_io,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(super::super::websocket::websocket_config()),
    )
    .await;
    let permits = Arc::new(Semaphore::new(1));
    let permit = permits.clone().try_acquire_owned().unwrap();
    let task = Task(tokio::spawn(async move {
        let _permit = permit;
        super::super::websocket::run_websocket_tunnel(
            ws,
            &legacy_auth(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            Some("192.0.2.10".parse().unwrap()),
            false,
        )
        .await
    }));
    settle().await;
    tokio::time::advance(Duration::from_secs(31)).await;
    settle().await;
    assert!(
        task.0.is_finished(),
        "WS upgrade alone cannot hold a connection forever"
    );
    assert_eq!(permits.available_permits(), 1);
}

#[tokio::test]
async fn relay_preauth_authenticated_carrier_releases_handshake_capacity() {
    let fixture = super::secure_tests::fixture(true);
    let (client_io, server_io) = tokio::io::duplex(8192);
    let (authenticated_tx, authenticated_rx) = tokio::sync::oneshot::channel();
    let server = fixture.server.clone();
    let _task = Task(tokio::spawn(async move {
        crate::session::serve_device_carrier(
            server_io,
            server,
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            Some("192.0.2.10".parse().unwrap()),
            move || {
                let _ = authenticated_tx.send(());
                Ok(())
            },
            None,
        )
        .await
    }));
    let _inner = fixture.client.connect(client_io).await.unwrap();
    authenticated_rx.await.unwrap();
    let mut held = Vec::new();
    for _ in 0..128 {
        held.push(
            fixture
                .server
                .try_acquire()
                .expect("authenticated session must release handshake pool"),
        );
    }
    assert!(
        fixture.server.try_acquire().is_err(),
        "handshake pool remains bounded"
    );
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_h2_handshake_cannot_restart_the_admission_clock() {
    let (client, server_io) = tokio::io::duplex(8192);
    let mut owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
    let registry = owner.registry();
    let admission = super::super::AdmissionBudget::new(Duration::from_millis(100));
    let server = Task(tokio::spawn(async move {
        handle_grpc_session_with_admission(
            server_io,
            &legacy_auth(),
            &TransportConfig::default(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            &registry,
            None,
            admission,
        )
        .await
    }));
    settle().await;
    tokio::time::advance(Duration::from_millis(70)).await;
    let (_sender, driver) = h2::client::handshake(client).await.unwrap();
    let _driver = Task(tokio::spawn(driver));
    settle().await;
    tokio::time::advance(Duration::from_millis(29)).await;
    settle().await;
    assert!(
        !server.0.is_finished(),
        "remaining original admission time is usable"
    );
    tokio::time::advance(Duration::from_millis(2)).await;
    settle().await;
    assert!(
        server.0.is_finished(),
        "H2 establishment must not grant a new timeout"
    );
    owner.shutdown().await;
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_websocket_upgrade_cannot_restart_the_admission_clock() {
    let (client, mut server_io) = tokio::io::duplex(8192);
    let admission = super::super::AdmissionBudget::new(Duration::from_millis(100));
    let server = Task(tokio::spawn(async move {
        super::super::websocket::handle_websocket_session_with_admission(
            &mut server_io,
            &legacy_auth(),
            &TransportConfig::default(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            admission,
        )
        .await
    }));
    settle().await;
    tokio::time::advance(Duration::from_millis(70)).await;
    let url = format!(
        "ws://relay.test{}",
        TransportConfig::default().websocket_path
    );
    let (_ws, _response) = tokio_tungstenite::client_async(url, client).await.unwrap();
    tokio::time::advance(Duration::from_millis(29)).await;
    settle().await;
    assert!(!server.0.is_finished());
    tokio::time::advance(Duration::from_millis(2)).await;
    settle().await;
    assert!(
        server.0.is_finished(),
        "WS upgrade must not grant a fresh admission timeout"
    );
}

#[tokio::test]
async fn relay_preauth_banned_peer_cannot_reach_capacity_admission() {
    let fixture = super::secure_tests::fixture(true);
    let held: Vec<_> = (0..128)
        .map(|_| fixture.server.try_acquire().unwrap())
        .collect();
    let limiter = RateLimiter::new(1, 60, true);
    let peer = "192.0.2.10".parse().unwrap();
    limiter.record_failure(peer).await;
    let (_client, carrier) = tokio::io::duplex(8192);
    crate::session::serve_device_carrier(
        carrier,
        fixture.server.clone(),
        &TargetPolicyConfig::default(),
        &limiter,
        Some(peer),
        || panic!("banned peer must not authenticate"),
        None,
    )
    .await
    .expect("known ban checked before exhausted capacity");
    drop(held);
    assert!(fixture.server.try_acquire().is_ok());
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_tls_and_dripping_http_headers_share_one_deadline() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let fixture = super::secure_tests::fixture(true);
    let config =
        crate::tls::load_server_config(&fixture.server_settings.cert, &fixture.server_settings.key)
            .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let (client_io, server_io) = tokio::io::duplex(8192);
    let permits = Arc::new(Semaphore::new(1));
    let permit = permits.clone().try_acquire_owned().unwrap();
    let mut owner = crate::lifecycle::TaskGroupRegistryOwner::new(Default::default());
    let registry = owner.registry();
    let admission = super::super::AdmissionBudget::new(Duration::from_millis(100));
    let server = Task(tokio::spawn(async move {
        let _permit = permit;
        let tls = tokio::time::timeout_at(admission.deadline, acceptor.accept(server_io))
            .await
            .unwrap()
            .unwrap();
        crate::session::handle_tls_session(
            tls,
            &legacy_auth(),
            "close",
            &crate::config::ServerLimits::default(),
            &TransportConfig::default(),
            &TargetPolicyConfig::default(),
            &RateLimiter::new(8, 60, false),
            "192.0.2.10:443".parse().unwrap(),
            None,
            &registry,
            None,
            admission,
        )
        .await
    }));
    settle().await;
    tokio::time::advance(Duration::from_millis(70)).await;
    let mut client = fixture.client.connect(client_io).await.unwrap();
    client.write_all(b"GET ").await.unwrap();
    client.flush().await.unwrap();
    settle().await;
    for _ in 0..2 {
        tokio::time::advance(Duration::from_millis(10)).await;
        client.write_all(b"x").await.unwrap();
        client.flush().await.unwrap();
        settle().await;
        assert!(!server.0.is_finished());
    }
    tokio::time::advance(Duration::from_millis(11)).await;
    settle().await;
    assert!(
        server.0.is_finished(),
        "dripping headers cannot reset the TCP/TLS admission clock"
    );
    assert_eq!(permits.available_permits(), 1);
    owner.shutdown().await;
}

fn valid_legacy_open() -> (TunnelAuthKeyring, Vec<u8>) {
    let token = b"synthetic-cutoff-regression-key";
    let auth = TunnelAuthKeyring {
        keys: vec![super::super::TunnelAuthKey {
            id: Arc::from("cutoff-test"),
            secret: Arc::from(token.as_slice()),
            legacy: false,
            not_after_unix_secs: None,
        }]
        .into(),
        operational_log: Default::default(),
        inner_tls: None,
        https_bridge: None,
        fronted_origin: None,
        relay_training: None,
    };
    let frame = aegis_core::tunnel::seal_tunnel_request(
        &TunnelRequest {
            host: "127.0.0.1".into(),
            port: 9,
        },
        token,
    )
    .unwrap();
    (auth, frame)
}

fn assert_original_cutoff_preserved(
    result: anyhow::Result<()>,
    admission: &super::super::AdmissionBudget,
    limiter: &super::super::admission::SocketAdmissionLimiter,
    activity: &super::super::https_bridge::Activity,
) {
    let error = result.expect_err("late valid proof must not authenticate");
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::TimedOut),
        "strict deadline keeps a typed timeout: {error:#}"
    );
    assert!(limiter.try_acquire("192.0.2.10".parse().unwrap()).is_none());
    assert_eq!(
        activity.deadline_with_timeout(admission.deadline, admission.timeout),
        Some(admission.deadline),
        "late proof cannot activate or renew connection activity"
    );
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_websocket_buffered_valid_proof_after_cutoff_is_refused() {
    use futures::SinkExt;
    let (client, server_io) = tokio::io::duplex(8192);
    let mut client = tokio_tungstenite::WebSocketStream::from_raw_socket(
        client,
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    let server = tokio_tungstenite::WebSocketStream::from_raw_socket(
        server_io,
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(super::super::websocket::websocket_config()),
    )
    .await;
    let limiter = super::super::admission::SocketAdmissionLimiter::new(1);
    let admission = super::super::AdmissionBudget::new(Duration::from_millis(100))
        .with_socket_permit(limiter.try_acquire("192.0.2.10".parse().unwrap()).unwrap());
    let activity = super::super::https_bridge::Activity::default();
    let (auth, frame) = valid_legacy_open();
    let policy = TargetPolicyConfig::default();
    let rate = RateLimiter::new(8, 60, false);
    let handling = super::super::websocket::run_websocket_tunnel_with_admission(
        server,
        &auth,
        &policy,
        &rate,
        "192.0.2.10:443".parse().unwrap(),
        None,
        false,
        admission.clone(),
        Some(activity.clone()),
    );
    tokio::pin!(handling);
    std::future::poll_fn(|cx| {
        assert!(handling.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    client
        .send(tokio_tungstenite::tungstenite::Message::Binary(frame))
        .await
        .unwrap();
    tokio::time::advance(Duration::from_millis(101)).await;
    assert_original_cutoff_preserved(handling.await, &admission, &limiter, &activity);
    drop(admission);
    assert!(limiter.try_acquire("192.0.2.10".parse().unwrap()).is_some());
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_grpc_buffered_valid_proof_after_cutoff_is_refused() {
    let (client, server_io) = tokio::io::duplex(8192);
    let (parts_tx, parts_rx) = tokio::sync::oneshot::channel();
    let _server = Task(tokio::spawn(async move {
        let mut connection = h2::server::handshake(server_io).await.unwrap();
        let parts = connection.accept().await.unwrap().unwrap();
        parts_tx.send(parts).ok().unwrap();
        while connection.accept().await.is_some() {}
    }));
    let (mut sender, driver) = h2::client::handshake(client).await.unwrap();
    let _driver = Task(tokio::spawn(driver));
    let request = http::Request::builder()
        .method("POST")
        .uri(TransportConfig::default().grpc_path)
        .body(())
        .unwrap();
    let (_response, mut send) = sender.send_request(request, false).unwrap();
    let (request, respond) = parts_rx.await.unwrap();
    let limiter = super::super::admission::SocketAdmissionLimiter::new(1);
    let admission = super::super::AdmissionBudget::new(Duration::from_millis(100))
        .with_socket_permit(limiter.try_acquire("192.0.2.10".parse().unwrap()).unwrap());
    let activity = super::super::https_bridge::Activity::default();
    let (auth, frame) = valid_legacy_open();
    let handling = handle_single_grpc_request(
        request,
        respond,
        GrpcRequestContext {
            witness: None,
            bridge_activity: Some(activity.clone()),
            transport: TransportConfig::default(),
            target_policy: TargetPolicyConfig::default(),
            auth_keyring: auth,
            rate_limiter: RateLimiter::new(8, 60, false),
            peer: "192.0.2.10:443".parse().unwrap(),
            bundle_ctx: None,
            admission: Some(admission.clone()),
        },
    );
    tokio::pin!(handling);
    std::future::poll_fn(|cx| {
        assert!(handling.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    send.send_data(grpc_frame(&frame), false).unwrap();
    settle().await;
    tokio::time::advance(Duration::from_millis(101)).await;
    assert_original_cutoff_preserved(handling.await, &admission, &limiter, &activity);
    drop(admission);
    assert!(limiter.try_acquire("192.0.2.10".parse().unwrap()).is_some());
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_device_buffered_valid_proof_after_cutoff_is_refused() {
    let mut fixture = super::secure_tests::fixture(true);
    fixture.server_settings.handshake_timeout_ms = 100;
    let server = aegis_core::secure_channel::Server::load(&fixture.server_settings).unwrap();
    let (client_io, server_io) = tokio::io::duplex(8192);
    let authenticated = Arc::new(AtomicUsize::new(0));
    let observed = authenticated.clone();
    let policy = TargetPolicyConfig::default();
    let rate = RateLimiter::new(8, 60, false);
    let serving = crate::session::serve_device_carrier(
        server_io,
        server.clone(),
        &policy,
        &rate,
        Some("192.0.2.10".parse().unwrap()),
        move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        None,
    );
    let connecting = fixture.client.connect(client_io);
    tokio::pin!(serving, connecting);
    let _client = std::future::poll_fn(|cx| {
        // Stop polling the server immediately when the client's final proof is
        // buffered; its next poll happens only after the original cutoff.
        assert!(serving.as_mut().poll(cx).is_pending());
        connecting.as_mut().poll(cx)
    })
    .await
    .unwrap();
    tokio::time::advance(Duration::from_millis(101)).await;
    let error = serving.await.unwrap_err();
    assert!(
        matches!(
            error
                .downcast_ref::<std::io::Error>()
                .and_then(aegis_core::secure_channel::AuthenticationFailure::from_io),
            Some(aegis_core::secure_channel::AuthenticationFailure::Timeout)
        ),
        "late TLS proof must preserve typed authentication timeout: {error:#}"
    );
    assert_eq!(authenticated.load(Ordering::SeqCst), 0);
    let held: Vec<_> = (0..128).map(|_| server.try_acquire().unwrap()).collect();
    assert!(server.try_acquire().is_err());
    drop(held);
}

#[tokio::test(start_paused = true)]
async fn relay_preauth_buffered_open_after_original_cutoff_cannot_contact_target() {
    let mut fixture = super::secure_tests::fixture(true);
    fixture.server_settings.handshake_timeout_ms = 100;
    let server = aegis_core::secure_channel::Server::load(&fixture.server_settings).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let policy = TargetPolicyConfig {
        profile: crate::config::TargetPolicyProfile::FullVpnEgress,
        allowed_ports: vec![target.port()],
    };
    let rate = RateLimiter::new(8, 60, false);
    let (client_io, server_io) = tokio::io::duplex(8192);
    let authenticated = Arc::new(AtomicUsize::new(0));
    let observed = authenticated.clone();
    let serving = crate::session::serve_device_carrier(
        server_io,
        server,
        &policy,
        &rate,
        None,
        move || {
            observed.fetch_add(1, Ordering::SeqCst);
            Ok(())
        },
        None,
    );
    let connecting = fixture.client.connect(client_io);
    tokio::pin!(serving, connecting);
    let mut client = std::future::poll_fn(|cx| {
        assert!(serving.as_mut().poll(cx).is_pending());
        connecting.as_mut().poll(cx)
    })
    .await
    .unwrap();
    std::future::poll_fn(|cx| {
        assert!(serving.as_mut().poll(cx).is_pending());
        std::task::Poll::Ready(())
    })
    .await;
    assert_eq!(authenticated.load(Ordering::SeqCst), 1);
    aegis_core::secure_channel::write_open(
        &mut client,
        &aegis_core::secure_channel::OpenRequest {
            version: 1,
            host: target.ip().to_string(),
            port: target.port(),
            transport: aegis_core::secure_channel::Transport::Tcp,
        },
    )
    .await
    .unwrap();
    tokio::time::advance(Duration::from_millis(101)).await;
    let error = serving.await.unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .map(std::io::Error::kind),
        Some(std::io::ErrorKind::TimedOut),
        "late Open must retain the original establishment timeout: {error:#}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(1), listener.accept())
            .await
            .is_err(),
        "late buffered Open must not contact its loopback target"
    );
}
